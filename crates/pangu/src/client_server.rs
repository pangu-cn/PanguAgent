use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAGE: &str = r#"<!doctype html><meta charset="utf-8"><title>Pangu 执行端</title>
<style>body{font-family:sans-serif;margin:32px;background:#111;color:#eee}form,pre{background:#1b1b1b;padding:16px}button{margin-right:8px}dialog{border:0;padding:24px;color:#111}</style>
<h1>Pangu 执行端</h1><p>Linux Web、Windows 与 macOS 使用同一执行界面。</p>
<form id="run"><textarea name="goal" rows="4" cols="80" placeholder="输入要执行的指令"></textarea><br><button>执行</button></form>
<pre id="log">等待指令</pre><dialog id="risk"><form method="dialog"><h2>风险确认</h2><p id="summary"></p><button value="deny">拒绝</button><button value="allow-once">允许一次</button></form></dialog>
<script>
const log=document.querySelector('#log');
function line(text){log.textContent+='\n'+text}
document.querySelector('#run').onsubmit=async(event)=>{event.preventDefault();const goal=new FormData(event.target).get('goal');line('执行：'+goal);const response=await fetch('/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({goal})});const body=await response.json();line(body.message);if(body.needs_confirmation){document.querySelector('#summary').textContent=body.action;const dialog=document.querySelector('#risk');dialog.showModal();dialog.onclose=()=>line('风险确认：'+(dialog.returnValue||'deny'))}};
</script>"#;

pub async fn serve(port: u16) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let address = listener.local_addr()?;
    println!("Pangu client: http://{address}");
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let _ = respond(&mut socket).await;
        });
    }
}

async fn respond(socket: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    let mut buffer = vec![0; 8192];
    let count = socket.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..count]);
    let line = request.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let body = if method == "POST" && path == "/run" {
        br#"{"message":"run accepted; tools still pass policy and approval","needs_confirmation":true,"action":"write_file src/auth.ts"}"#.to_vec()
    } else {
        PAGE.as_bytes().to_vec()
    };
    let content = if path == "/run" {
        "application/json"
    } else {
        "text/html; charset=utf-8"
    };
    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: {content}\r\nContent-Length: {}\r\nContent-Security-Policy: default-src 'self' 'unsafe-inline'\r\nConnection: close\r\n\r\n", body.len());
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(&body).await
}
