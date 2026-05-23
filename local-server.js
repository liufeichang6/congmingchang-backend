// local-server.js
const app = require('./api/index'); // 导入你真正的后端代码
const PORT = 3000;

app.listen(PORT, () => {
    console.log(`🚀 聪明肠后端服务器运行在 http://localhost:${PORT}`);
    console.log('📌 API 接口前缀: /api');
    console.log('🔑 默认管理员账号: admin / admin123');
});