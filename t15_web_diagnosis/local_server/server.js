const express = require('express');
const app = express();
const PORT = 3000;

// 1. NORMAL (Chạy chuẩn 200 OK)
app.get('/normal', (req, res) => {
    res.status(200).send("OK Normal");
});

// 2. HTTP_PROBLEM (Nghẽn TTFB - Kéo dài thời gian xử lý 4 giây)
app.get('/slow-server', (req, res) => {
    setTimeout(() => {
        res.status(200).send("Response Delayed by 4s");
    }, 4000);
});

// 3. HTTP_PROBLEM (Trả về Status Code lỗi 500 / 503)
app.get('/error-500', (req, res) => {
    res.status(500).send("Internal Server Error");
});

app.get('/error-503', (req, res) => {
    res.status(503).send("Service Unavailable");
});

// 4. HTTP_PROBLEM (Server chủ động hủy kết nối giữa chừng)
app.get('/drop-connection', (req, res) => {
    res.socket.destroy();
});

app.listen(PORT, () => {
    console.log(`[Lab Server] Fault injection running at http://localhost:${PORT}`);
});