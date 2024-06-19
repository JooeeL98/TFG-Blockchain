import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template
import requests
from uuid import uuid4
from urllib.parse import urlparse
import sqlite3

class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash='0')
        self.nodes = set()
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                     id INTEGER PRIMARY KEY,
                     area TEXT,
                     documento TEXT,
                     nombre TEXT,
                     fecha_creacion TEXT,
                     descripcion TEXT)''')
        conn.commit()
        conn.close()
    
    def get_file_metadata(self):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('SELECT * FROM files')
        rows = c.fetchall()
        conn.close()
        return rows

    def get_file_by_name(self, nombre):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('SELECT * FROM files WHERE nombre = ?', (nombre,))
        rows = c.fetchone()
        conn.close()
        return rows

    def add_file_metadata(self, metadata):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('''INSERT INTO files (area, documento, nombre, fecha_creacion, descripcion)
                     VALUES (?, ?, ?, ?, ?)''', 
                     (metadata.get('area'), metadata.get('documento'), metadata.get('nombre'), metadata.get('fecha_creacion'), metadata.get('descripcion')))
        conn.commit()
        id = c.lastrowid  # Obtener el ID del nuevo registro
        conn.close()
        return id

    def delete_file_metadata(self, nombre):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('SELECT * FROM files WHERE nombre = ?', (nombre,))
        file_data = c.fetchone()
        if file_data:
            c.execute('DELETE FROM files WHERE nombre = ?', (nombre,))
            conn.commit()
        conn.close()
        return file_data

    def update_file_name(self, old_name, new_name):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('SELECT * FROM files WHERE nombre = ?', (old_name,))
        file_data = c.fetchone()
        if file_data:
            c.execute('UPDATE files SET nombre = ? WHERE nombre = ?', (new_name, old_name))
            conn.commit()
        conn.close()
        return file_data

    def update_file_document(self, name, new_document):
        conn = sqlite3.connect('metadata.db')
        c = conn.cursor()
        c.execute('SELECT * FROM files WHERE nombre = ?', (name,))
        file_data = c.fetchone()
        if file_data:
            c.execute('UPDATE files SET documento = ? WHERE nombre = ?', (new_document, name))
            conn.commit()
        conn.close()
        return file_data

    def add_nodes(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            print(node)
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json().get('length')
                chain = response.json().get('chain')

                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
            
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
    
    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'nonce': proof,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions}
        self.transactions = []
        self.chain.append(block)
        return block
    
    def add_transaction(self, sender, receiver, movimiento, codigo):
        transaction_hash = self.hash({'sender': sender, 'receiver': receiver, 'movimiento': movimiento})
        movimiento['hash'] = transaction_hash

        self.transactions.append({'sender': sender,
                                  'receiver': receiver,
                                  'movimiento': {'accion': movimiento['accion'], 'codigo': codigo},
                                  'hash': transaction_hash})
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1
    
    def get_previous_block(self):
        return self.chain[-1]
    
    def get_block(self):
        return self.chain
    
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            
            if hash_operation[:3] == '000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        new_proof = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['nonce']
            proof = block['nonce']
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:3] == '000':
                return False
            
            previous_block = block
            block_index += 1
        return True


# Preparo la aplicacion
app = Flask(__name__)

# Se genera un ID unico para cada nodo
node_address = str(uuid4()).replace('-', '')

# Creando Blockchain
blockchain = Blockchain()

# Ruta de la pagina web
@app.route('/')
def index():
    return render_template('index.html')

# Minando un nuevo bloque
@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['nonce']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Felicidades haz minado un bloque!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'nonce': block['nonce'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']}
    return jsonify(response), 200

# Obteniendo una cadena completa
@app.route('/get_chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        block_data = {
            'index': block['index'],
            'timestamp': block['timestamp'],
            'nonce': block['nonce'],
            'previous_hash': block['previous_hash'],
            'transactions': []
        }
        for tx in block['transactions']:
            tx_data = {
                'movimiento': tx['movimiento'],
                'receiver': tx['receiver'],
                'sender': tx['sender'],
                'hash': tx['hash']
            }
            block_data['transactions'].append(tx_data)
        chain_data.append(block_data)
    
    response = {'chain': chain_data,
                'length': len(chain_data)}
    return jsonify(response), 200

# Para ver si la cadena es valida
@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'Todo bien. La blockchain es valida'}
    else:
        response = {'message': 'Hubo un problema! La blockchain no es valida'}
    
    return jsonify(response), 200

# Agregando nueva transaccion al blockchain
@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['receiver', 'movimiento']
    if not all(key in json for key in transaction_keys):
        return 'Algun elemento de la transaccion esta faltando', 400
    
    code = ""
    movimiento = json['movimiento']
    if movimiento['accion'] == 'crear':
        metadata = {
            'area': movimiento.get('area'),
            'documento': movimiento.get('documento'),
            'nombre': movimiento.get('nombre'),
            'fecha_creacion': movimiento.get('fecha_creacion'),
            'descripcion': movimiento.get('descripcion')
        }
        file_id = blockchain.add_file_metadata(metadata)
        movimiento['id'] = file_id  # Agregar el ID a la transacción
        movimiento['codigo'] = f"{file_id}{movimiento.get('area', '')}{movimiento.get('documento', '')}"
        code = movimiento['codigo']
    elif movimiento['accion'] == 'eliminar':
        nombre = movimiento.get('nombre')
        file_data = blockchain.get_file_by_name(nombre)
        if file_data:
            file_id, area, documento, nombre, fecha_creacion, descripcion = file_data
            movimiento['codigo'] = f"{file_id}{area}{documento}"
        else:
            return 'Archivo no encontrado', 404
        blockchain.delete_file_metadata(nombre)
        code = movimiento['codigo']
    elif movimiento['accion'] == 'modificar_nombre':
        old_name = movimiento.get('nombre')
        new_name = movimiento.get('nuevo_nombre')
        file_data = blockchain.update_file_name(old_name, new_name)
        if file_data:
            file_id, area, documento, nombre, fecha_creacion, descripcion = file_data
            movimiento['codigo'] = f"{file_id}{area}{documento}"
        else:
            return 'Archivo no encontrado', 404
        code = movimiento['codigo']
    elif movimiento['accion'] == 'modificar_documento':
        documento = movimiento.get('nombre')
        new_document = movimiento.get('nuevo_documento')
        file_data = blockchain.update_file_document(documento, new_document)
        if file_data:
            file_id, area, documento, nombre, fecha_creacion, descripcion = file_data
            movimiento['codigo'] = f"{file_id}{area}{new_document}"
        else:
            return 'Archivo no encontrado', 404
        code = movimiento['codigo']
    elif movimiento['accion'] == 'acceder':
        name = movimiento.get('nombre')
        file_data = blockchain.get_file_by_name(name)
        if file_data:
            file_id, area, documento, nombre, fecha_creacion, descripcion = file_data
            movimiento['codigo'] = f"{file_id}{area}{documento}"
        else:
            return 'Archivo no encontrado', 404
        code = movimiento['codigo']
    
    index = blockchain.add_transaction(sender=node_address, receiver=json['receiver'], movimiento=movimiento, codigo=code)
    response = {'message': f'La transaccion sera anyadida al Bloque {index}'}
    return jsonify(response), 201


# Descentralizando la Blockchain

# Conectando nuevos Nodos
@app.route('/connect_node', methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "no Node", 401
    for node in nodes:
        blockchain.add_nodes(node)
    response = {'message': 'Nodos conectados:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

# Reemplazando la cadena por la mas larga
@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replace = blockchain.replace_chain()
    if is_chain_replace:
        response = {'message': 'Los nodos tenian diferentes cadenas asi que la cadena fue remplazada por la mas larga',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'Todo bien, la cadena es la mas larga',
                    'actual_chain': blockchain.chain}
    
    return jsonify(response), 200

@app.route('/view_data', methods=['GET'])
def view_data():
    data = blockchain.get_file_metadata()
    if data is None:
        data = []
    return render_template('view_data.html', data=data)

# Corriendo App
app.run(host='0.0.0.0', port='5002')
