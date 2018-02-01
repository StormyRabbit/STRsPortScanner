#!/bin/python3
from flask import Flask, request, jsonify
from portScanner import PortScanner
from exporters import *
from encryptionMgr import EncryptionMgr
import socket
app = Flask(__name__)
# APPLICATION OBJECTS
ps = PortScanner()
xmlExp = XMLExporter()
em = EncryptionMgr()
db = SqlExporter()

# TEMPLATE VARIABLES
app.secret_key = "HEMLIS"
navigation = [{'toolName': 'Port Scan'}]


@app.route("/createKeyFile", methods=['POST'])
def create_key_file():
    # end point for creating a encryption key file.ascii
    em.create_rnd_key_file(request.get_json()['file_name']) 
    return "200"


@app.route("/loadKeyFile", methods=['POST'])
def load_key_file():
    # endpoitn for loading a encryption key and returns the keys filename.
    try:
        em.load_key_file(request.get_json()['file_name'])
        return jsonify(request.get_json()['file_name']) 
    except:
        return "error"


@app.route("/loadXML", methods=['POST'])
def _load_result_xml():
    # clears the stored data and loads a new set of data from the provided filename.
    # returns a json of the new data.
    ps.result.clear()
    ps.result = xmlExp.load_from_xml(request.get_json()['file_name'])
    return jsonify(ps.result)


@app.route("/saveEncryptedXML", methods=['POST'])
def save_encrypted_xml():
    # creates a lxml tree from the currently stored data.
    # converts to XML string and the nsends it to the encryption manager.
    xml_result = xmlExp.create_xml(ps.result)
    xml_string = xmlExp.stringify(xml_result)
    em.save_with_key_file(request.get_json()['file_name'], xml_string)
    return "200"


@app.route("/removeEntry", methods=['POST'])
def remove_entry():
    # end point for removing a single entry provided in the request json.
    ip_dict = ps.result[request.get_json()['mode']][request.get_json()['ip']]
    port_list = ip_dict['open_ports'].remove(int(request.get_json()['port']))
    mode_dict = ps.result[request.get_json()['mode']]
    if not port_list:
        del mode_dict[request.get_json()['ip']]
    return "200"


@app.route("/getResult")
def get_result():
    # returns all the models results.
    return jsonify(ps.result)


@app.route("/loadEncryptedXML", methods=['POST'])
def load_encrypted_xml():
    # clears the currently loaded data.
    # loads the encrypted data in the encryption manager
    # decrypts it and loads it to the result structure.
    ps.result.clear()
    em.load_encrypted_file(request.get_json()['file_name'])
    decrypted_xml = em.decrypt(em.encrypted_data, em.loadedKey)
    ps.result = xmlExp.load_from_xml_string(decrypted_xml)
    return jsonify(ps.result) 



@app.route("/saveXML", methods=['POST'])
def _save_result_xml():
    # takes the currently stored results and sends it to the XML exporter 
    # that converts it to lxml tree object and then writes to file.
    xml = xmlExp.create_xml(ps.result)
    xmlExp.write_xml_to_file(xml, request.get_json()['file_name'])
    return "200"


@app.route("/importDB", methods=['POST'])
def db_import():
    # clears the currently loaded data
    # connects to the database with credentials provided in request.
    # loads all the data from the database and returns a json of it.
    try:
        ps.result.clear()
        db.connect(request.get_json()['server'], request.get_json()['db'], request.get_json()['user'], request.get_json()['pw'])
        ps.result = db.load_from_mysql()
        db.disconnect()
        return jsonify(ps.result)
    except:
        return "error" 


@app.route("/exportDB", methods=['POST'])
def db_export():
    # connects to the database provided in the request json.
    # export all the currently loaded results to it.
    try:
        db.connect(request.get_json()['server'], request.get_json()['db'], request.get_json()['user'], request.get_json()['pw'])
        db.export_to_mysql(ps.result)
        db.disconnect()
        return "200"
    except:
        return "error"


@app.route("/startScan", methods=['POST'])
def start_scan():
    # takes data provided in the request json and starts a scan process with it.
    address = request.get_json()['address']
    port_low = int(request.get_json()['sPort'])
    port_high = int(request.get_json()['ePort'])
    mode = request.get_json()['mode']
    ps.scan_address(address, port_low_end=port_low, port_high_end=port_high, mode=mode)
    return jsonify(ps.result)


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
