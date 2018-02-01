from lxml import etree
import pymysql


class SqlExporter:
    def __init__(self):
        self.connection = None
        self.cursor = None

    def connect(self, host, database, user, password):
        # connect the connection object to the database using the parameters.
        self.connection = pymysql.connect(host, user, password, database)
        self.cursor = self.connection.cursor()
        pass

    def disconnect(self):
        # disconnect from the db
        if self.connection is not None:
            self.connection.close()

    def _create_table(self):
        # creates the needed db tables if they do not exist.
        if self.connection is None:
            raise TypeError("Connection is None, call connect first")
        tcp_table = "CREATE TABLE IF NOT EXISTS TCPScan(ADDRESS CHAR(15) NOT NULL, PORT CHAR(5) NOT NULL, PRIMARY KEY (ADDRESS, PORT))"
        udp_table = "CREATE TABLE IF NOT EXISTS UDPScan(ADDRESS CHAR(15) NOT NULL, PORT CHAR(5) NOT NULL, PRIMARY KEY (ADDRESS, PORT))"

        self.cursor.execute(tcp_table)
        self.cursor.execute(udp_table)
        self.connection.commit()

    def export_to_mysql(self, results):
        # takes the dictionary in the incoming parameter and inserts it into the database.
        if self.connection is None:
            raise TypeError("Connection is None, call connect first")
        self._create_table()
        for entry, result in results['tcp'].items():
            for port in result['open_ports']:
                self._insert_into_db(entry, port, 'tcp')
        for entry, result in results['udp'].items():
            for port in result['open_ports']:
                self._insert_into_db(entry, port, 'udp')

    def _insert_into_db(self, entry, port, mode):
        # inserts parameters to the db.
        if mode == 'tcp':
            insert_query = "INSERT INTO TCPScan(ADDRESS, PORT) VALUES ('%s', '%s');" % (entry, port)
        if mode == 'udp':
            insert_query = "INSERT INTO UDPScan(ADDRESS, PORT) VALUES ('%s', '%s');" % (entry, port)
        try:
            self.cursor.execute(insert_query)
            self.connection.commit()
        except pymysql.InternalError:
            self.connection.rollback()

    def _execute_query(self, query):
        # executes a query string and then returns the data.
        try:
            self.cursor.execute(query)
            return self.cursor.fetchall()
        except pymysql.InternalError:
            pass

    def _build_dictionary(self, tcp_results, udp_results):
        # builds a dictionary from sql result objects.
        ret_struct = {'tcp': {}, 'udp': {}}
        for row in tcp_results:
            ret_struct['tcp'][row[0]] = {'open_ports': []}
        for row in tcp_results:
            ret_struct['tcp'][row[0]]['open_ports'].append(row[1])
        for row in udp_results:
            ret_struct['udp'][row[0]] = {'open_ports': []}
        for row in udp_results:
            ret_struct['udp'][row[0]]['open_ports'].append(row[1])
        return ret_struct

    def load_from_mysql(self):
        # loads all results from the database tables and returns a dictionary from them.
        tcp = self._execute_query("SELECT * FROM TCPScan")
        udp = self._execute_query("SELECT * FROM UDPScan")
        return self._build_dictionary(tcp, udp)


class XMLExporter:

    @staticmethod
    def write_xml_to_file(tree, file_name):
        # takes a lxml tree objects and writes it to xml file
        etree.ElementTree(tree).write(file_name, pretty_print=True, xml_declaration=True, encoding="utf-8")

    @staticmethod
    def encrypted_write_xml_to_file(em, tree, key, file_name):
        # encrypts a xml tree and encrypts it and then writes to file.
        encrypted_tree = em.encrypt(tree, key)
        em.write_encrypted_to_file(encrypted_tree, file_name)

    @staticmethod
    def stringify(xml):
        # converts the xml parmeter to a string representation.
        return etree.tostring(xml)

    def create_xml(self, results):
        # takes a result dictionary and converts it to lxml tree structure.
        root = etree.Element("PortScanResults")
        for ip, result in results['tcp'].items():
            self._build_xml_from_dict(ip, result, 'tcp', root)
        for ip, result in results['udp'].items():
            print(ip)
            self._build_xml_from_dict(ip, result, 'udp', root)
        return root

    def _build_xml_from_dict(self, ip, result, mode, root):
        # adds subelements to root containg the data in parameters.
        if mode == 'tcp':
            entity = etree.SubElement(root, 'TcpScanEntity')
        if mode == 'udp':
            entity = etree.SubElement(root, 'UdpScanEntity')
        ip_address = etree.SubElement(entity, 'ip')
        ip_address.text = ip
        for port in result['open_ports']:
            etree.SubElement(entity, 'port').text = str(port)

    def load_from_xml_string(self, xml_string):
        # converts a lxml xml string to a dictionary.
        ret_struct = {'tcp': {}, 'udp': {}}
        root = etree.fromstring(xml_string)
        print(etree.tostring(root, pretty_print=True))
        for _, b in etree.iterwalk(root, tag='TcpScanEntity'):
            self._build_from_xml(ret_struct, b, 'tcp')
        for _, b in etree.iterwalk(root, tag='UdpScanEntity'):
            self._build_from_xml(ret_struct, b, 'udp')
        return ret_struct

    def load_from_xml(self, file_name):
        # loads a xml file and converts it to a dictionary structure.
        ret_struct = {'tcp': {}, 'udp': {}}
        for _, b in etree.iterparse(file_name, tag='TcpScanEntity'):
            self._build_from_xml(ret_struct, b, 'tcp')
        for _, b in etree.iterparse(file_name, tag='UdpScanEntity'):
            print(b)
            self._build_from_xml(ret_struct, b, 'udp')
        return ret_struct

    def _build_from_xml(self, structure, tag, mode):
        # helper subroutine for load_from_xml, puts xml obejcts into dict struct.
        current_address = None
        for entry in tag:
            if entry.tag == 'ip':
                current_address = entry.text
                structure[mode][current_address] = {'open_ports': []}
            if entry.tag == 'port':
                structure[mode][current_address]['open_ports'].append(entry.text)

