let $ = require('jquery');
const {ipcRenderer} = require('electron');

ipcRenderer.on('scanResult', (event, arg) => {
    // activates when main.js recieves scan data from the model, edits the dom with new table data.
    if(arg['udp'])
        buildTable('udp');
    if(arg['tcp'])
        buildTable('tcp');
        function buildTable(mode) {
            for(let ip in arg[mode]) {
                for(let port in arg[mode][ip]['open_ports']) {
                    let table = null;
                    if(mode === 'tcp')
                        table = document.getElementById("tcpResultTable");
                    if(mode === 'udp')
                        table = document.getElementById("udpResultTable");
                    let row = table.insertRow(table.length);
                    row.onclick = highlight;
                    row.marked = false;
                    row.clickable = true;
                    row.insertCell(0).innerText = ip;
                    row.insertCell(1).innerText = arg[mode][ip]['open_ports'][port];
                }
            }
        // hide the loader and display the tables.
        $('#loader').addClass("hide-loader");
        document.getElementById("tcpDiv").style.visibility = "visible";
        document.getElementById("udpDiv").style.visibility = "visible";
        }


});
// ipcRenderer.on calls activated when this file gets data from main.js
ipcRenderer.on('sqlModal', (event, arg) => {
   document.getElementById('id01').style.display='block';
});

ipcRenderer.on('keyLoaded', (event, arg) => {
    document.getElementById("keyLoaded").style.visibility = "visible";
    let str = "LOADED ENCRYPTION KEY: ";
    let argSplit = arg.split("/");
    let fileName = argSplit[argSplit.length-1];
    document.getElementById("keyLoaded").textContent = str.concat(fileName);
});


ipcRenderer.on('customPacketResponse', (event, arg) => {
   document.getElementById("customPacketResponseArea").innerHTML = JSON.stringify(arg);
});
// end of ipcRenderer.on calls


function startScan() {
    // function called when start button is pressed.

    // hides the tables and displays the loader animation.
    document.getElementById("tcpDiv").style.visibility = "hidden";
    document.getElementById("udpDiv").style.visibility = "hidden";
    $('#loader').removeClass("hide-loader");
    
    // removes the old table rows.
    let table = document.getElementById('tcpResultTable');
    while(table.rows.length > 1)
        table.deleteRow(-1);

    // selects what mode the scan should use.
    let mode = null;
    if(document.getElementById("tcpRadio").checked)
        mode = 'tcp';
    if(document.getElementById("udpRadio").checked)
        mode = 'udp';

    // create the payload sent to the main.js and later to app.py to start 
    // processing the scan request.
    let payload = {
        'address': document.getElementById("address").value,
        'sPort': document.getElementById("sPort").value,
        'ePort': document.getElementById("ePort").value,
        'mode': mode,

    };
    // transmitt payload.
    sendToMain('startScan', payload);
}

function ioSQL(s) {
    // function to start the I/O processes for the MySQL process.
    let payload = {
        'server': document.getElementById("sqlServer").value,
        'db': document.getElementById("sqlDB").value,
        'user': document.getElementById("sqlUser").value,
        'pw': document.getElementById("sqlPW").value

    };
    (s === 'import') ? sendToMain('importSQL', payload) : sendToMain('exportSQL', payload);
    document.getElementById('id01').style.display='none'
}


function sendToMain(e, d) {
    // sends the event and its data to main.js
    ipcRenderer.send(e, d);
}

function openTab(evt, tabName) {
    // used for changing tabs between tcp and udp.
    var i, x, tablinks;
    x = document.getElementsByClassName("scanResults");
    for (i = 0; i < x.length; i++) {
        x[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablink");
    for (i = 0; i < x.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" w3-red", "");
    }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " w3-red";
}


function tcpFilter() {
    // filters the table after inputted ip address.
    var input, filter, table, tr, td, i;
    input = document.getElementById("tcpFilter");
    filter = input.value.toUpperCase();
    table = document.getElementById("tcpResultTable");
    tr = table.getElementsByTagName("tr");

    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td")[0];
        if (td) {
            if (td.innerHTML.toUpperCase().indexOf(filter) > -1) {
                tr[i].style.display = "";
            } else {
                tr[i].style.display = "none";
            }
        }
    }
}

function udpFilter() {
    // filters the table after inputted ip address.
    var input, filter, table, tr, td, i;
    input = document.getElementById("udpFilter");
    filter = input.value.toUpperCase();
    table = document.getElementById("udpResultTable");
    tr = table.getElementsByTagName("tr");

    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td")[0];
        if (td) {
            if (td.innerHTML.toUpperCase().indexOf(filter) > -1) {
                tr[i].style.display = "";
            } else {
                tr[i].style.display = "none";
            }
        }
    }
}

highlight = function() {
    // function for highlighting table rows when clicked on.
    let table = document.getElementById('tcpResultTable');
    for(let i=0; i < table.rows.length; i++) {
        table.rows[i].onclick = function () {
            if(this.clickable) {
                if(!this.marked) {
                    unmarkMarked();
                    this.style.backgroundColor = "red";
                    this.marked = true;
                }else {
                    this.style.backgroundColor = "#FFF";
                    this.marked = false;
                }
            }
        }
    }
    function unmarkMarked() {
        // unmarks anyrow that is already marked.
        for(let i = 0; i < table.rows.length; i++) {
            table.rows[i].style.backgroundColor = "#FFF";
            table.rows[i].marked = false;
        }
    }
};

function removeMarked() {
    // sends a request to the responsible process to remove a scan entry.
    let table = document.getElementById('tcpResultTable');
    for(let i = 0; i < table.rows.length; i++) {
        if(table.rows[i].style.backgroundColor === "red") {
            let payload = {
                'ip': table.rows[i].cells[0].innerHTML,
                'port': table.rows[i].cells[1].innerHTML,
                'mode': 'tcp'
            };
            table.deleteRow(i);
            sendToMain('removeEntry', payload);
        }
    }
}