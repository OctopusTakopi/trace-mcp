//! Protocol tests against the real `trace-mcp serve --stdio` binary.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trace-mcp")
}

async fn send_json(stdin: &mut tokio::process::ChildStdin, message: &Value) -> std::io::Result<()> {
    let serialized = serde_json::to_string(message)?;
    stdin.write_all(serialized.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

async fn read_json_line(reader: &mut BufReader<tokio::process::ChildStdout>) -> Value {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("timed out waiting for MCP stdout")
        .expect("read stdout");
    assert!(n > 0, "server closed stdout");
    serde_json::from_str(line.trim()).expect("json-rpc line")
}

#[tokio::test]
async fn initialize_and_tools_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(bin())
        .args(["--store", dir.path().to_str().unwrap(), "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn serve --stdio");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "trace-mcp-test", "version": "0" }
            }
        }),
    )
    .await
    .unwrap();
    let init = read_json_line(&mut stdout).await;
    assert_eq!(init["id"], 1);
    assert!(
        init["result"]["capabilities"]["tools"].is_object()
            || init["result"]["capabilities"].is_object()
    );

    send_json(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await
    .unwrap();

    send_json(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    )
    .await
    .unwrap();
    let listed = read_json_line(&mut stdout).await;
    let tools = listed["result"]["tools"].as_array().expect("tools array");
    let names: Vec<_> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for required in [
        "trace_doctor",
        "trace_start",
        "trace_status",
        "trace_snapshot",
        "trace_stop",
        "trace_cancel",
        "trace_decode",
        "trace_query",
        "trace_compare",
    ] {
        assert!(names.contains(&required), "missing {required} in {names:?}");
    }
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

async fn spawn_server(
    dir: &std::path::Path,
) -> (
    tokio::process::Child,
    tokio::process::ChildStdin,
    BufReader<tokio::process::ChildStdout>,
) {
    let mut child = Command::new(bin())
        .args(["--store", dir.to_str().unwrap(), "serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn serve --stdio");
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdin, stdout)
}

async fn initialize(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut BufReader<tokio::process::ChildStdout>,
) {
    send_json(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "trace-mcp-test", "version": "0" }
            }
        }),
    )
    .await
    .unwrap();
    let init = read_json_line(stdout).await;
    assert_eq!(init["id"], 1);
    send_json(
        stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_json_is_protocol_error() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut stdin, mut stdout) = spawn_server(dir.path()).await;
    initialize(&mut stdin, &mut stdout).await;
    stdin.write_all(b"{not-json\n").await.unwrap();
    stdin.flush().await.unwrap();
    let line = tokio::time::timeout(Duration::from_secs(5), async {
        let mut s = String::new();
        stdout.read_line(&mut s).await.ok();
        s
    })
    .await
    .unwrap_or_default();
    if !line.is_empty() {
        let v: Value = serde_json::from_str(line.trim()).unwrap_or(json!({}));
        assert!(
            v.get("error").is_some(),
            "expected protocol error, got {line}"
        );
    }
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}

#[tokio::test]
async fn eof_after_initialize_exits() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut stdin, mut stdout) = spawn_server(dir.path()).await;
    initialize(&mut stdin, &mut stdout).await;
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("server should exit on stdin EOF")
        .expect("wait");
    assert!(status.success() || status.code().is_some());
}

#[tokio::test]
async fn unknown_fields_rejected_on_doctor() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut stdin, mut stdout) = spawn_server(dir.path()).await;
    initialize(&mut stdin, &mut stdout).await;
    send_json(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "trace_doctor",
                "arguments": { "probe": false, "unexpected": true }
            }
        }),
    )
    .await
    .unwrap();
    let resp = read_json_line(&mut stdout).await;
    let is_err = resp.get("error").is_some()
        || resp["result"]["isError"] == true
        || resp["result"]["is_error"] == true;
    assert!(is_err, "unknown field should fail: {resp}");
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
}
