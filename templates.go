package main

import (
	"html/template"
	"net/url"
)

// Template helpers and HTML templates (dark mode)

var tplFuncs = template.FuncMap{
	"pathescape": url.PathEscape,
}

var loginTpl = template.Must(template.New("login").Funcs(tplFuncs).Parse(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Login - gums3</title>
<style>
  :root {
    color-scheme: dark;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0b0b0b;
    color: #eaeaea;
    margin: 0; padding: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .container {
    background: #121212;
    border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.6);
    padding: 40px; max-width: 420px; width: 90%; border: 1px solid #2a2a2a;
  }
  .logo { text-align: center; margin-bottom: 30px; }
  .logo h1 { margin: 0; font-size: 2.4em; font-weight: 700; color: #eaeaea; }
  .logo p { margin: 6px 0 0; color: #b8b8b8; font-size: 0.95em; }
  label { display: block; margin: 14px 0 6px; font-weight: 500; color: #d6d6d6; }
  input {
    width: 100%; padding: 12px; box-sizing: border-box; border: 1px solid #333;
    border-radius: 8px; font-size: 16px; background: #1e1e1e; color: #eaeaea;
  }
  input::placeholder { color: #8a8a8a; }
  input:focus { outline: none; border-color: #555; }
  button {
    margin-top: 22px; width: 100%; padding: 14px; font-size: 16px; font-weight: 600;
    background: #eaeaea; color: #0b0b0b; border: none; border-radius: 8px; cursor: pointer;
  }
  button:hover { filter: brightness(92%); }
  a { color: #eaeaea; }
</style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <h1>gums3</h1>
      <p>Elegant S3 Storage Viewer</p>
    </div>
    <form method="POST" action="/login">
      <label>Endpoint URL:
        <input type="text" name="endpoint" placeholder="http://minio.example.com:9000" required>
      </label>
      <label>Access Key:
        <input type="text" name="access-key" required>
      </label>
      <label>Secret Key:
        <input type="password" name="secret-key" required>
      </label>
      <label>Region:
        <input type="text" name="region" value="us-east-1" required>
      </label>
      <label>Default Bucket (optional):
        <input type="text" name="bucket" placeholder="my-bucket">
      </label>
      <button type="submit">Connect to S3</button>
    </form>
  </div>
</body>
</html>
`))

var pageTpl = template.Must(template.New("page").Funcs(tplFuncs).Parse(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>gums3</title>
<style>
  :root { color-scheme: dark; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0; padding: 20px; background: #0b0b0b; color: #eaeaea; min-height: 100vh;
  }
  .header {
    background: #121212;
    color: #eaeaea; padding: 20px; border-radius: 12px; margin-bottom: 26px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.5); border: 1px solid #2a2a2a;
  }
  .header h1 { margin: 0; font-size: 2.0em; font-weight: 700; }
  .header p { margin: 6px 0 0; opacity: 0.9; }
  a { text-decoration: none; color: #eaeaea; font-weight: 500; }
  a:hover { text-decoration: underline; }
  .breadcrumbs {
    margin-bottom: 18px; padding: 10px 12px; background: #121212; border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.4); font-size: 14px; border: 1px solid #2a2a2a;
  }
  .breadcrumbs a { margin-right: 8px; }
  .bucket-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 18px; margin: 18px 0;
  }
  .bucket-card {
    background: #121212; border-radius: 12px; padding: 20px; text-align: center;
    box-shadow: 0 2px 14px rgba(0,0,0,0.5); transition: all 0.2s ease; border: 1px solid #2a2a2a;
  }
  .bucket-card:hover {
    transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.6);
    background: #161616;
  }
  .bucket-icon { font-size: 2.2em; margin-bottom: 10px; }
  .bucket-name { font-size: 1.05em; font-weight: 600; color: #eaeaea; }
  table {
    border-collapse: collapse; width: 100%; background: #121212; border-radius: 12px;
    overflow: hidden; box-shadow: 0 2px 14px rgba(0,0,0,0.5); border: 1px solid #2a2a2a;
  }
  th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #262626; }
  th {
    background: #1f1f1f; color: #eaeaea;
    font-weight: 600; text-transform: uppercase; font-size: 0.82em; letter-spacing: 0.4px;
  }
  tr { background: #121212; }
  tr:nth-child(even) { background: #161616; }
  tr:hover { background: #1a1a1a; }
  .folder td a { font-weight: 600; color: #eaeaea; }
  .file-name {
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 0.9em; word-break: break-all;
  }
  .actions { white-space: nowrap; }
  .btn {
    padding: 6px 12px; border-radius: 6px; font-size: 0.85em; font-weight: 500;
    text-decoration: none; margin-right: 8px; display: inline-block;
  }
  .btn-download { background: #eaeaea; color: #0b0b0b; border: 1px solid #2a2a2a; }
  .btn-download:hover { filter: brightness(92%); }
  .btn-delete { background: #1e1e1e; color: #eaeaea; border: 1px solid #2a2a2a; cursor: pointer; }
  .btn-delete:hover { background: #242424; }
  .empty-state {
    text-align: center; padding: 50px; background: #121212; border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.5); border: 1px solid #2a2a2a;
  }
  .empty-icon { font-size: 3.6em; margin-bottom: 20px; opacity: 0.5; }
  .muted { color: #b8b8b8; }
  .header-actions { margin-top: 8px; }
  .header-actions a { margin-right: 12px; }
  .logout { color: #f88; }
  .logout:hover { color: #faa; }
  .hint { font-size: 0.9em; color: #b8b8b8; }
</style>
</head>
<body>
  <div class="header">
    <h1>gums3</h1>
    <p>Elegant S3 Storage Viewer</p>
    <div class="header-actions"><a class="logout" href="/logout">Logout</a></div>
  </div>
  
  {{if .Buckets}}
    <h2 style="margin: 22px 0 12px;">📦 Your Buckets</h2>
    <div class="bucket-grid">{{range .Buckets}}
      <a href="/bucket/{{.}}" class="bucket-card">
        <div class="bucket-icon">🪣</div>
        <div class="bucket-name">{{.}}</div>
      </a>
    {{end}}</div>
  {{end}}
  
  {{if .Bucket}}
    <div class="breadcrumbs">
      🏠 <a href="/">Buckets</a> / 
      🪣 <a href="/bucket/{{.Bucket}}">{{.Bucket}}</a>
      {{range .Breadcrumb}}
        / 📁 <a href="/bucket/{{$.Bucket}}/{{.Path}}">{{.Name}}</a>
      {{end}}
    </div>
    
    {{if or .Folders .Objects}}
      <table>
        <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead>
        <tbody>
          {{range .Folders}}
            <tr class="folder">
              <td><a href="/bucket/{{$.Bucket}}/{{pathescape .Path}}">📁 <span class="file-name">{{.Name}}</span></a></td>
              <td>—</td><td>—</td><td></td>
            </tr>
          {{end}}
          {{range .Objects}}
            <tr>
              <td>📄 <span class="file-name">{{.Name}}</span></td>
              <td>{{.SizeStr}}</td>
              <td>{{.DateStr}}</td>
              <td class="actions">
                <a href="/download?bucket={{urlquery $.Bucket}}&key={{urlquery .Key}}" class="btn btn-download">⬇️ Download</a>
                <form method="POST" action="/delete" style="display:inline"
                      onsubmit="return confirm('Are you sure you want to delete this object?');">
                  <input type="hidden" name="bucket" value="{{$.Bucket}}">
                  <input type="hidden" name="key"    value="{{.Key}}">
                  <input type="hidden" name="prefix" value="{{$.Prefix}}">
                  <input type="hidden" name="csrf"   value="{{$.CSRF}}">
                  <button class="btn btn-delete" type="submit">🗑️ Delete</button>
                </form>
              </td>
            </tr>
          {{end}}
        </tbody>
      </table>
    {{else}}
      <div class="empty-state">
        <div class="empty-icon">📂</div>
        <h3>This bucket is empty</h3>
        <p class="muted">No files or folders found in this location.</p>
      </div>
    {{end}}
  {{end}}
</body>
</html>
`))
