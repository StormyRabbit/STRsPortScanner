const {app, BrowserWindow, ipcMain, Menu, dialog} = require('electron');
const url = require('url');
const http = require('http');
const path = require('path');

let win = null;

function createWindow() {
  // function for creating the window and spawning the model application.
 let python = require('child_process').spawn('python', ['./model/app.py']);
  win = new BrowserWindow({width: 600, height: 600});
  win.loadURL(
    url.format({
      pathname: path.join(__dirname, 'index.html'),
      protocol: 'file:',
      slashes: true,
    }),
  );
  win.on('closed', function() {
    win = null;
    python.kill('SIGINT');
  } )
}

// ipcMain.on events, activates when the first parameter is sent from the view.js.
ipcMain.on('removeEntry', (event, arg) => {
  requestOptions['path'] = '/removeEntry';
  sendJSON(arg);
});

ipcMain.on('startScan', (event, arg) => {
  requestOptions['path'] = '/startScan';
  sendJSON(arg, resultCallback);

});

ipcMain.on('importSQL', (event, arg) => {
  requestOptions['path'] = '/importDB';
  sendJSON(arg, resultCallback);
});

ipcMain.on('exportSQL', (event, arg) => {
  requestOptions['path'] = '/exportDB';
  sendJSON(arg);
});
// stop of ipcMain.on events

// structure defining the layout of the menu bar and its onclick effects.
const template = [
  {
    label: 'XML',
    submenu: [
      {
        label: 'Open XML',
        click() {
          dialog.showOpenDialog({properties: ['openFile']}, loadXML);
        },
      },
      {
        label: 'Open Encrypted XML',
        click() {
          dialog.showOpenDialog({properties: ['openFile']}, loadEncryptedXML);
        },
      },
      {
        label: 'Save XML',
        click() {
          dialog.showSaveDialog({properties: ['saveFile']}, saveXML);
        },
      },
      {
        label: 'Save Encrypted XML',
        click() {
          dialog.showSaveDialog({properties: ['saveFile']}, saveEncryptedXML);
        },
      },
    ],
  },
  {
    label: 'Encryption Keys',
    submenu: [
      {
        label: 'Load Key File',
        click() {
          dialog.showOpenDialog({properties: ['openFile']}, loadKeyFile);
        },
      },
      {
        label: 'Create Key File',
        click() {
          dialog.showSaveDialog({properties: ['saveFile']}, createKeyFile);
        },
      },
    ],
  },
  {
    label: 'MySQL',
    click() {
      win.webContents.send('sqlModal', 'asd');
    },
  },
];

// template for sending requests to the model.
const requestOptions = {
  method: 'POST',
  protocol: 'http:',
  hostname: 'localhost',
  port: 5000,
  path: '/saveXML',
  headers: {
    'Content-Type': 'application/json',
  },
};

/* CALLBACKS USED FOR COMMUNICATION BETWEEN MAIN.js VIEW.js and app.y */
createKeyFile = function(fileName) {
  if(fileName) {
    requestOptions['path'] = '/createKeyFile';
    sendFileName(fileName);
  }
};

loadKeyFile = function(fileName) {
    if(fileName) {
        requestOptions['path'] = '/loadKeyFile';
        sendFileName(fileName[0], encryptionCallback);
    }
};

loadXML = function(filePath) {
  if(filePath) {
    requestOptions['path'] = '/loadXML';
    sendFileName(filePath[0], resultCallback);
  }
};

loadEncryptedXML = function(filePath) {
  if(filePath) {
      requestOptions['path'] = '/loadEncryptedXML';
      sendFileName(filePath[0], resultCallback);
  }
};

saveEncryptedXML = function(filePath) {
  if(filePath) {
      requestOptions['path'] = '/saveEncryptedXML';
      sendFileName(filePath);
  }
};

saveXML = function(filePath) {
  if(filePath) {
      requestOptions['path'] = 'saveXML';
      sendFileName(filePath);

  }
};

resultCallback = function(response) {
  response.on('data', function(chunk) {
    try {
      let answer = JSON.parse(chunk);
      console.log(JSON.stringify(answer))
      win.webContents.send('scanResult', answer);
    } catch (err) {}
  });
};

encryptionCallback = function(response) {
  response.on('data', function(chunk) {
    try {
      let answer = JSON.parse(chunk);
      win.webContents.send('keyLoaded', answer);
    } catch (err) {}
  });
};

devNull = function(response) {
  response.on('data', function(chunk) {
  });
};

function sendJSON(payload, cb) {
  // sends a json payload to the model
  let req = http.request(requestOptions, cb);
  req.write(JSON.stringify(payload));
  req.end();
}

function sendFileName(fileName, cb) {
  // sends a json containing a filename to the model
  req = http.request(requestOptions, cb);
  req.write(JSON.stringify({file_name: fileName}));
  req.end();
}

// creates and sets the menu bar
const menu = Menu.buildFromTemplate(template);
Menu.setApplicationMenu(menu);
app.on('ready', createWindow);
