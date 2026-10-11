use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAGE: &str = r#"<!doctype html><meta charset="utf-8"><title>Pangu Web</title>
<style>body{margin:0;background:#18181b;color:#f4f4f5;font-family:Segoe UI,sans-serif}main{max-width:920px;margin:40px auto}textarea,pre{width:100%;background:#27272a;color:inherit;border:1px solid #3f3f46;border-radius:8px}dialog{border:0;border-radius:12px;padding:24px}</style>
<main><h1>Pangu Web</h1><p>Linux 执行端。风险确认使用弹窗。</p><form id="run"><textarea rows="5" placeholder="输入指令"></textarea><p><button>执行</button></p></form><pre id="log">等待指令</pre></main>
<dialog id="risk"><form method="dialog"><h2>风险确认</h2><p id="summary"></p><button value="deny">拒绝</button><button value="allow-once">允许一次</button></form></dialog>
<script>const log=document.querySelector('#log');document.querySelector('#run').onsubmit=async(e)=>{e.preventDefault();const goal=e.target.querySelector('textarea').value;log.textContent+='\n执行：'+goal;const r=await fetch('/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({goal})});const b=await r.json();document.querySelector('#summary').textContent=b.action;const d=document.querySelector('#risk');d.showModal();d.onclose=()=>log.textContent+='\n确认：'+(d.returnValue||'deny')}</script>"#;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 8789)).await?;
    println!("pangu-web: http://127.0.0.1:8789");
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let count = socket.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..count]);
            let post = request.starts_with("POST /run");
            let body: &[u8] = if post { br#"{"action":"write_file src/auth.ts"}"# } else { PAGE.as_bytes() };
            let kind = if post { "application/json" } else { "text/html; charset=utf-8" };
            let header = format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(body).await;
        });
    }
}
