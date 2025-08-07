package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dustin/go-humanize"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
)

// HTML templates moved to templates.go (dark mode)

// ─── SESSION STORE & AWS CLIENT ─────────────────────

type cred struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Region    string
	Bucket    string
}

var sessions = struct {
	sync.RWMutex
	m map[string]cred
}{m: make(map[string]cred)}

// serverSecret is generated at process start and used to bind CSRF tokens to session IDs
var serverSecret []byte

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func getCred(w http.ResponseWriter, r *http.Request) (cred, bool) {
	ck, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return cred{}, false
	}
	sessions.RLock()
	c, ok := sessions.m[ck.Value]
	sessions.RUnlock()
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return cred{}, false
	}
	return c, true
}

func newConfig(c cred) (aws.Config, error) {
	// Base loaders
	region := strings.TrimSpace(c.Region)
	if region == "" {
		// let AWS default chain resolve region if not provided
		region = "us-east-1"
	}
	loaders := []func(*config.LoadOptions) error{config.WithRegion(region)}

	// If static credentials provided, use them; otherwise rely on default AWS chain
	if c.AccessKey != "" && c.SecretKey != "" {
		loaders = append(loaders, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""),
		))
	}

	// If a custom endpoint is provided (e.g., MinIO), set a resolver
	if strings.TrimSpace(c.Endpoint) != "" {
		resolver := aws.EndpointResolverWithOptionsFunc(
			func(svc, region string, opts ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: c.Endpoint, SigningRegion: region}, nil
			},
		)
		loaders = append(loaders, config.WithEndpointResolverWithOptions(resolver))
	}

	return config.LoadDefaultConfig(context.TODO(), loaders...)
}

func newClient(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
}

// csrfForSession computes an HMAC-based token for the provided session ID
func csrfForSession(sessionID string) string {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// withSecureHeaders adds basic security headers to responses
func withSecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// ─── HTTP HANDLERS ────────────────────────────────

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s ← %s", r.Method, r.URL.Path, r.RemoteAddr)
	if r.Method == http.MethodGet {
		if err := loginTpl.Execute(w, nil); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
		}
		return
	}
	endpoint := r.FormValue("endpoint")
	ak := r.FormValue("access-key")
	sk := r.FormValue("secret-key")
	region := r.FormValue("region")
	bucket := strings.TrimSpace(r.FormValue("bucket"))
	if endpoint == "" || ak == "" || sk == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}
	sid, err := newSessionID()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	sessions.Lock()
	sessions.m[sid] = cred{Endpoint: endpoint, AccessKey: ak, SecretKey: sk, Region: region, Bucket: bucket}
	sessions.Unlock()
	// Cookie security attributes; Secure may be disabled with --insecure for local HTTP
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   !insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   4 * 60 * 60, // 4 hours
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s ← %s", r.Method, r.URL.Path, r.RemoteAddr)
	c, ok := getCred(w, r)
	if !ok {
		return
	}
	// If a default bucket is set in the session, redirect to it
	if b := strings.TrimSpace(c.Bucket); b != "" {
		http.Redirect(w, r, "/bucket/"+b, http.StatusSeeOther)
		return
	}
	cfg, err := newConfig(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := newClient(cfg)
	out, err := client.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var bs []string
	for _, b := range out.Buckets {
		bs = append(bs, *b.Name)
	}
	if err := pageTpl.Execute(w, struct{ Buckets []string }{bs}); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func bucketHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s ← %s", r.Method, r.URL.Path, r.RemoteAddr)
	c, ok := getCred(w, r)
	if !ok {
		return
	}
	cfg, err := newConfig(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := newClient(cfg)
	raw := strings.TrimPrefix(r.URL.Path, "/bucket/")
	parts := strings.SplitN(raw, "/", 2)
	bucket := parts[0]
	prefix := ""
	if len(parts) > 1 {
		prefix = parts[1]
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	type crumb struct{ Name, Path string }
	var bc []crumb
	if prefix != "" {
		segs := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
		acc := ""
		for _, s := range segs {
			acc += s + "/"
			bc = append(bc, crumb{s, acc})
		}
	}
	resp, err := client.ListObjectsV2(r.Context(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix), Delimiter: aws.String("/"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type folder struct{ Name, Path string }
	type file struct {
		Name, Key string
		Size      int64
		SizeStr   string
		DateStr   string
	}
	data := struct {
		Buckets    []string
		Bucket     string
		Prefix     string
		Breadcrumb []crumb
		Folders    []folder
		Objects    []file
		CSRF       string
	}{Bucket: bucket, Prefix: prefix, Breadcrumb: bc}
	for _, cp := range resp.CommonPrefixes {
		full := *cp.Prefix
		name := strings.TrimSuffix(strings.TrimPrefix(full, prefix), "/")
		data.Folders = append(data.Folders, folder{name, full})
	}
	for _, o := range resp.Contents {
		if *o.Key == prefix {
			continue
		}
		size := *o.Size
		mod := ""
		if o.LastModified != nil {
			mod = o.LastModified.Local().Format("2006-01-02 15:04:05")
		}
		data.Objects = append(data.Objects, file{
			Name:    strings.TrimPrefix(*o.Key, prefix),
			Key:     *o.Key,
			Size:    size,
			SizeStr: humanize.Bytes(uint64(size)),
			DateStr: mod,
		})
	}
	if ck, err := r.Cookie("session"); err == nil {
		data.CSRF = csrfForSession(ck.Value)
	}
	if err := pageTpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s ← %s", r.Method, r.URL.Path, r.RemoteAddr)
	c, ok := getCred(w, r)
	if !ok {
		return
	}
	cfg, err := newConfig(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := newClient(cfg)
	bucket := r.URL.Query().Get("bucket")
	key := r.URL.Query().Get("key")
	obj, err := client.GetObject(r.Context(), &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer obj.Body.Close()
	fname := filepath.Base(key)
	esc := url.PathEscape(fname)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", esc))
	w.Header().Set("Content-Type", "application/octet-stream")
	if obj.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*obj.ContentLength, 10))
	}
	if _, err := io.Copy(w, obj.Body); err != nil {
		log.Printf("stream error: %v", err)
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s ← %s", r.Method, r.URL.Path, r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, ok := getCred(w, r)
	if !ok {
		return
	}
	// CSRF protection: validate token bound to session cookie
	ck, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	csrfPosted := r.FormValue("csrf")
	if csrfPosted == "" || csrfPosted != csrfForSession(ck.Value) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg, err := newConfig(c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := newClient(cfg)
	bucket := r.FormValue("bucket")
	key := r.FormValue("key")
	prefix := r.FormValue("prefix")
	if _, err := client.DeleteObject(r.Context(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirect := "/bucket/" + bucket
	if prefix != "" {
		redirect += "/" + strings.TrimSuffix(prefix, "/")
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Remove server-side session if present
	if ck, err := r.Cookie("session"); err == nil {
		sessions.Lock()
		delete(sessions.m, ck.Value)
		sessions.Unlock()
	}
	// Expire the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !insecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ─── COBRA & TUI ───────────────────────────────────

var (
	port       int
	configFile string
	rootCmd    = &cobra.Command{Use: "gums3", Short: "gums3 - Elegant S3 Storage Viewer"}
	serverCmd  = &cobra.Command{Use: "server", Short: "Run beautiful web interface", Run: runServer}
	cliCmd     = &cobra.Command{Use: "cli", Short: "Run interactive TUI", Run: runCLI}
	insecure   bool
	bucketFlag string
)

func init() {
	serverCmd.Flags().IntVarP(&port, "port", "p", 8080, "HTTP port")
	serverCmd.Flags().BoolVar(&insecure, "insecure", false, "Disable secure cookie; allow HTTP for local development")
	cliCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to credentials JSON")
	cliCmd.Flags().StringVarP(&bucketFlag, "bucket", "b", "", "Open a specific bucket (skip ListBuckets)")
	rootCmd.AddCommand(serverCmd, cliCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// generate server secret for CSRF tokens
	serverSecret = make([]byte, 32)
	if _, err := rand.Read(serverSecret); err != nil {
		log.Fatalf("failed to init server secret: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/bucket/", bucketHandler)
	mux.HandleFunc("/download", downloadHandler)
	mux.HandleFunc("/delete", deleteHandler)
	mux.HandleFunc("/healthz", healthzHandler)

	handler := withSecureHeaders(mux)

	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("gums3 server: http://localhost%s/", addr)

	// graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func runCLI(cmd *cobra.Command, args []string) {
	var c cred
	var configLoaded bool

	// 1) Try --config flag
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			// First try direct struct unmarshal
			if err := json.Unmarshal(data, &c); err == nil {
				c.Endpoint = strings.TrimSpace(c.Endpoint)
				c.AccessKey = strings.TrimSpace(c.AccessKey)
				c.SecretKey = strings.TrimSpace(c.SecretKey)
				c.Region = strings.TrimSpace(c.Region)
				if c.Endpoint != "" && c.AccessKey != "" && c.SecretKey != "" {
					configLoaded = true
				}
			}
			// Fallback: accept multiple key variants from JSON
			if !configLoaded {
				var raw map[string]any
				if err := json.Unmarshal(data, &raw); err == nil {
					// helper to fetch any of the provided keys
					get := func(keys ...string) string {
						for _, k := range keys {
							if v, ok := raw[k]; ok {
								if s, ok := v.(string); ok {
									return strings.TrimSpace(s)
								}
							}
						}
						// try case-insensitive lookup
						for rk, v := range raw {
							for _, k := range keys {
								if strings.EqualFold(rk, k) {
									if s, ok := v.(string); ok {
										return strings.TrimSpace(s)
									}
								}
							}
						}
						return ""
					}
					if c.Endpoint == "" {
						c.Endpoint = get("Endpoint", "endpoint", "url", "endpoint_url", "AWS_ENDPOINT_URL_S3")
					}
					if c.AccessKey == "" {
						c.AccessKey = get("AccessKey", "access_key", "accessKey", "AWS_ACCESS_KEY_ID")
					}
					if c.SecretKey == "" {
						c.SecretKey = get("SecretKey", "secret_key", "secretKey", "AWS_SECRET_ACCESS_KEY")
					}
					if c.Region == "" {
						c.Region = get("Region", "region", "AWS_REGION")
					}
					if c.Region == "" {
						c.Region = "us-east-1"
					}
					if c.Endpoint != "" && c.AccessKey != "" && c.SecretKey != "" {
						configLoaded = true
					}
				}
			}
			if configLoaded {
				log.Printf("loaded credentials from file: %s", configFile)
			}
		} else {
			log.Printf("could not read config file %s: %v", configFile, err)
		}
	}

	// 2) Try default path if flag didn't work
	if !configLoaded {
		usr, err := user.Current()
		if err == nil {
			defaultPath := filepath.Join(usr.HomeDir, ".gums3", "credentials.json")
			data, err := os.ReadFile(defaultPath)
			if err == nil {
				err = json.Unmarshal(data, &c)
				if err == nil && c.Endpoint != "" && c.AccessKey != "" && c.SecretKey != "" {
					configLoaded = true
				}
			}
		}
	}

	// 3) Try environment variables
	if !configLoaded {
		if ak := os.Getenv("AWS_ACCESS_KEY_ID"); ak != "" {
			c.AccessKey = ak
		}
		if sk := os.Getenv("AWS_SECRET_ACCESS_KEY"); sk != "" {
			c.SecretKey = sk
		}
		if rg := os.Getenv("AWS_REGION"); rg != "" {
			c.Region = rg
		}
		if ep := os.Getenv("AWS_ENDPOINT_URL_S3"); ep != "" { // AWS SDK v2 standard env
			c.Endpoint = ep
		} else if ep := os.Getenv("S3_ENDPOINT"); ep != "" { // common alt
			c.Endpoint = ep
		}
		if c.Region == "" {
			c.Region = "us-east-1"
		}
		if c.AccessKey != "" && c.SecretKey != "" {
			configLoaded = true
			log.Printf("loaded credentials from environment")
		}
	}

	// 4) Interactive prompt if no config found
	if !configLoaded {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Endpoint URL: ")
		endpoint, _ := reader.ReadString('\n')
		fmt.Print("Access Key: ")
		ak, _ := reader.ReadString('\n')
		fmt.Print("Secret Key: ")
		sk, _ := reader.ReadString('\n')
		fmt.Print("Region (default us-east-1): ")
		region, _ := reader.ReadString('\n')

		c.Endpoint = strings.TrimSpace(endpoint)
		c.AccessKey = strings.TrimSpace(ak)
		c.SecretKey = strings.TrimSpace(sk)
		c.Region = strings.TrimSpace(region)
		if c.Region == "" {
			c.Region = "us-east-1"
		}
	}

	cfg, err := newConfig(c)
	if err != nil {
		log.Printf("failed to load config: %v", err)
		return
	}
	client := newClient(cfg)

	var buckets []string
	if strings.TrimSpace(bucketFlag) != "" {
		buckets = []string{bucketFlag}
	} else {
		out, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
		if err != nil {
			log.Printf("failed to list buckets: %v\nHint: if your credentials cannot list all buckets, try: gums3 cli --bucket <bucket-name>", err)
			return
		}
		if len(out.Buckets) == 0 {
			log.Printf("no buckets found")
			return
		}
		buckets = make([]string, len(out.Buckets))
		for i, b := range out.Buckets {
			buckets[i] = *b.Name
		}
	}

	app := tview.NewApplication()
	rootTable := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	rootTable.SetCell(0, 0, tview.NewTableCell("🪣 gums3 BUCKETS").SetAttributes(tcell.AttrBold))
	for i, name := range buckets {
		rootTable.SetCell(i+1, 0, tview.NewTableCell("  "+name))
	}

	rootTable.SetSelectedFunc(func(row, col int) {
		if row == 0 {
			return
		}
		go showBucketTUI(app, client, buckets[row-1], "", rootTable)
	})

	rootTable.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Rune() == 'q' || ev.Rune() == 'Q' {
			app.Stop()
			return nil
		}
		return ev
	})

	if err := app.SetRoot(rootTable, true).EnableMouse(true).Run(); err != nil {
		return
	}
}

func showBucketTUI(app *tview.Application, client *s3.Client, bucket, prefix string, prev tview.Primitive) {
	resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})
	if err != nil {
		// Show error in TUI instead of just logging
		app.QueueUpdateDraw(func() {
			errorText := fmt.Sprintf("❌ Error accessing %s/%s:\n\n%v\n\nPress Esc to go back", bucket, prefix, err)
			errorView := tview.NewTextView().
				SetText(errorText).
				SetTextAlign(tview.AlignCenter).
				SetDoneFunc(func(key tcell.Key) {
					if key == tcell.KeyEscape {
						app.SetRoot(prev, true)
					}
				})
			app.SetRoot(errorView, true)
		})
		return
	}

	type entry struct{ Name, Key, Kind, Size, Date string }
	var entries []entry
	for _, cp := range resp.CommonPrefixes {
		full := *cp.Prefix
		name := strings.TrimSuffix(strings.TrimPrefix(full, prefix), "/")
		entries = append(entries, entry{name, full, "📁", "", ""})
	}
	for _, o := range resp.Contents {
		if *o.Key == prefix {
			continue
		}
		size := *o.Size
		name := strings.TrimPrefix(*o.Key, prefix)
		// Clean the filename to prevent display corruption
		name = strings.ReplaceAll(name, "\n", "")
		name = strings.ReplaceAll(name, "\r", "")
		mod := ""
		if o.LastModified != nil {
			mod = o.LastModified.Local().Format("2006-01-02 15:04:05")
		}
		entries = append(entries, entry{name, *o.Key, "📄", humanize.Bytes(uint64(size)), mod})
	}

	app.QueueUpdateDraw(func() {
		table := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
		table.SetCell(0, 0, tview.NewTableCell("TYPE").SetAttributes(tcell.AttrBold))
		table.SetCell(0, 1, tview.NewTableCell("NAME").SetAttributes(tcell.AttrBold))
		table.SetCell(0, 2, tview.NewTableCell("SIZE").SetAttributes(tcell.AttrBold))
		table.SetCell(0, 3, tview.NewTableCell("MODIFIED").SetAttributes(tcell.AttrBold))
		for i, e := range entries {
			table.SetCell(i+1, 0, tview.NewTableCell(e.Kind))
			table.SetCell(i+1, 1, tview.NewTableCell(e.Name))
			table.SetCell(i+1, 2, tview.NewTableCell(e.Size))
			table.SetCell(i+1, 3, tview.NewTableCell(e.Date))
		}

		info := tview.NewTextView().
			SetText("gums3 │ Enter: download │ D: delete │ Esc: back │ Q: quit").
			SetTextAlign(tview.AlignCenter)

		flex := tview.NewFlex().
			SetDirection(tview.FlexRow).
			AddItem(table, 0, 1, true).
			AddItem(info, 1, 1, false)

		table.SetSelectedFunc(func(row, col int) {
			if row == 0 {
				return
			}
			e := entries[row-1]
			if e.Kind == "📁" {
				go showBucketTUI(app, client, bucket, e.Key, table)
				return
			}
			app.QueueUpdateDraw(func() {
				statusText := fmt.Sprintf("⬇️ Downloading %s...", e.Name)
				statusView := tview.NewTextView().SetText(statusText).SetTextAlign(tview.AlignCenter)
				app.SetRoot(statusView, false)
			})

			obj, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
				Bucket: aws.String(bucket), Key: aws.String(e.Key),
			})
			if err != nil {
				app.QueueUpdateDraw(func() {
					errorText := fmt.Sprintf("❌ Download failed: %v\n\nPress any key to continue", err)
					errorView := tview.NewTextView().
						SetText(errorText).
						SetTextAlign(tview.AlignCenter).
						SetDoneFunc(func(key tcell.Key) {
							go showBucketTUI(app, client, bucket, prefix, prev)
						})
					app.SetRoot(errorView, true)
				})
				return
			}
			defer obj.Body.Close()

			filename := filepath.Base(e.Key)
			f, err := os.Create(filename)
			if err != nil {
				app.QueueUpdateDraw(func() {
					errorText := fmt.Sprintf("❌ Failed to create file: %v\n\nPress any key to continue", err)
					errorView := tview.NewTextView().
						SetText(errorText).
						SetTextAlign(tview.AlignCenter).
						SetDoneFunc(func(key tcell.Key) {
							go showBucketTUI(app, client, bucket, prefix, prev)
						})
					app.SetRoot(errorView, true)
				})
				return
			}
			defer f.Close()

			if _, err := io.Copy(f, obj.Body); err != nil {
				app.QueueUpdateDraw(func() {
					errorText := fmt.Sprintf("❌ Failed to write file: %v\n\nPress any key to continue", err)
					errorView := tview.NewTextView().
						SetText(errorText).
						SetTextAlign(tview.AlignCenter).
						SetDoneFunc(func(key tcell.Key) {
							go showBucketTUI(app, client, bucket, prefix, prev)
						})
					app.SetRoot(errorView, true)
				})
			} else {
				app.QueueUpdateDraw(func() {
					successText := fmt.Sprintf("✅ Downloaded %s successfully!\n\nPress any key to continue", filename)
					successView := tview.NewTextView().
						SetText(successText).
						SetTextAlign(tview.AlignCenter).
						SetDoneFunc(func(key tcell.Key) {
							go showBucketTUI(app, client, bucket, prefix, prev)
						})
					app.SetRoot(successView, true)
				})
			}
		})

		table.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			switch {
			case ev.Rune() == 'd' || ev.Rune() == 'D':
				row, _ := table.GetSelection()
				if row == 0 {
					return nil
				}
				e := entries[row-1]
				if e.Kind == "📁" {
					return nil
				}
				modal := tview.NewModal().
					SetText(fmt.Sprintf("Delete '%s'?", e.Name)).
					AddButtons([]string{"Cancel", "Delete"}).
					SetDoneFunc(func(idx int, label string) {
						if label == "Delete" {
							if _, err := client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
								Bucket: aws.String(bucket), Key: aws.String(e.Key),
							}); err != nil {
								app.QueueUpdateDraw(func() {
									errorText := fmt.Sprintf("❌ Delete failed: %v\n\nPress any key to continue", err)
									errorView := tview.NewTextView().
										SetText(errorText).
										SetTextAlign(tview.AlignCenter).
										SetDoneFunc(func(key tcell.Key) {
											go showBucketTUI(app, client, bucket, prefix, prev)
										})
									app.SetRoot(errorView, true)
								})
								return
							}
							// Success - show confirmation
							app.QueueUpdateDraw(func() {
								successText := fmt.Sprintf("✅ Deleted %s successfully!\n\nPress any key to continue", e.Name)
								successView := tview.NewTextView().
									SetText(successText).
									SetTextAlign(tview.AlignCenter).
									SetDoneFunc(func(key tcell.Key) {
										go showBucketTUI(app, client, bucket, prefix, prev)
									})
								app.SetRoot(successView, true)
							})
						} else {
							go showBucketTUI(app, client, bucket, prefix, prev)
						}
					})
				app.SetRoot(modal, false)
				return nil
			case ev.Rune() == 'q' || ev.Rune() == 'Q':
				app.Stop()
				return nil
			}
			return ev
		})

		table.SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEscape {
				if prefix == "" {
					app.SetRoot(prev, true)
				} else {
					up := strings.TrimSuffix(prefix, "/")
					parts := strings.Split(up, "/")
					parent := ""
					if len(parts) > 1 {
						parent = strings.Join(parts[:len(parts)-1], "/") + "/"
					}
					go showBucketTUI(app, client, bucket, parent, prev)
				}
			}
		})

		app.SetRoot(flex, true)
	})
}
