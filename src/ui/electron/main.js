const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const net = require('net');

let mainWindow;
let pipeClient;
let isConnected = false;
const PIPE_NAME = '\\\\.\\pipe\\star_daemon';

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#121212',
        icon: path.join(__dirname, '../react/public/star-radar.svg'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true
        }
    });

    // In dev, load from Parcel/Vite. In prod, load index.html
    // We will assume "npm run dev" is used which starts Vite at 5173

    // Check if we are running via 'electron .' manually or via npm script
    // We'll try localhost first
    mainWindow.loadURL('http://localhost:5173').then(() => {
        console.log("Loaded URL, checking connection...");
        if (isConnected) {
            mainWindow.webContents.send('star-event', 'System Connected');
        }
    }).catch(() => {
        mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
    });

    mainWindow.webContents.on('did-finish-load', () => {
        if (isConnected) {
            mainWindow.webContents.send('star-event', 'System Connected');
        }
    });

    mainWindow.on('closed', function () {
        mainWindow = null;
    });

    // Handshake listener for UI
    ipcMain.on('request-status', (event) => {
        console.log("IPC: Received request-status. isConnected:", isConnected);
        if (isConnected) {
            event.reply('star-event', 'System Connected');
        } else {
            event.reply('star-event', 'Disconnected');
        }
    });

    connectToDaemon();
}

function connectToDaemon() {
    console.log(`Connecting to ${PIPE_NAME}...`);
    pipeClient = net.connect(PIPE_NAME, () => {
        console.log('Connected to S.T.A.R. Daemon!');
        isConnected = true;
        if (mainWindow) {
            mainWindow.webContents.send('star-event', 'System Connected');
        }
    });

    pipeClient.on('data', (data) => {
        // Data might be multiple lines
        const lines = data.toString().split('\n');
        lines.forEach(line => {
            if (line.trim()) {
                console.log("Daemon says:", line);
                if (mainWindow) {
                    mainWindow.webContents.send('star-event', line);
                }
            }
        });
    });

    pipeClient.on('end', () => {
        console.log('Disconnected from daemon.');
        isConnected = false;
        if (mainWindow) mainWindow.webContents.send('star-event', 'Disconnected');
    });

    pipeClient.on('error', (err) => {
        console.log('Pipe error:', err.message);
        // Retry connection after 2 seconds
        if (!isConnected) {
            setTimeout(connectToDaemon, 2000);
        }
    });
}

app.on('ready', createWindow);

app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
});

app.on('activate', function () {
    if (mainWindow === null) createWindow();
});
