from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
import requests
from auth import auth_user, auth_password  
import urllib3
from users import users  
import base64
import time
import re
from datetime import datetime
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configuración básica del logging
logging.basicConfig(
    filename='app.log',  # El archivo donde se guardarán los logs
    level=logging.DEBUG,  # Nivel de logging (puedes usar DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(message)s',  # Formato del log
)

# Ahora puedes registrar eventos en cualquier parte del código
logging.info('Aplicación iniciada.')


# URL base de QRadar
QRADAR_URL_BASE = 'https://192.168.46.1/api/'
QRADAR_OFFENSES = f'{QRADAR_URL_BASE}siem/offenses'
QRADAR_OFFENSES_CLOSING_REASONS = f'{QRADAR_URL_BASE}siem/offense_closing_reasons'
QRADAR_SEARCHES = f'{QRADAR_URL_BASE}/ariel/searches'


# Autenticación para la API de QRadar
QRADAR_AUTH = (auth_user, auth_password)
QRADAR_REQUEST_HEADERS = {
    'Version': '16.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}


QRADAR_REQUEST_HEADERS2 = {
    'Version': '20.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

app = Flask(__name__)
app.secret_key = 'xxxxxxxxxxxxxxxxxxxxxxx'  


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  

class User(UserMixin):
    def __init__(self, username):
        self.id = username

# Cargar el usuario
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

# INICIO DE SESION
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('gestion')) 
        else:
            flash('Credenciales incorrectas', 'danger')

    return render_template('index.html')  

# Ruta de cierre de sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index')) 

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/ofensas')
@login_required
def ofensas():
    return render_template('ofensas.html')


@app.route('/usuarios')
@login_required
def usuarios():
    return render_template('usuarios.html')


@app.route('/razon_cierre')
@login_required
def razon_cierre():
    return render_template('razon_cierre.html')

@app.route('/gestion')
@login_required
def gestion():
    return render_template('gestion.html')

@app.route('/logs')
@login_required
def show_logs():
    try:
        with open('app.log', 'r') as file:
            logs = file.readlines()  # Lee todas las líneas del archivo de log
        logs = ''.join(logs)  # Convierte la lista de líneas en un solo string
        return render_template('logs.html', logs=logs)
    except FileNotFoundError:
        return render_template('error.html', error_message="No se encontró el archivo de logs.")




#  OBTENER RAZON DE CIERRE
@app.route('/api/get_closing_reasons', methods=['GET'])
def get_closing_reasons():
    url_closing_reason = f"{QRADAR_OFFENSES_CLOSING_REASONS}"
    response = requests.get(url_closing_reason, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
    
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "No se pudo obtener las razones de cierre"}), 500
    
#  OBTENER USUARIOS
@app.route('/api/get_usuarios', methods=['GET'])
def get_usuarios():
    url_user_asig = f"{QRADAR_OFFENSES}/200469/assignable_actors"
    response = requests.get(url_user_asig, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
    
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "No se pudo obtener los usuarios disponibles"}), 500
    

# CERRAR OFENSAS
@app.route('/api/close_offense', methods=['POST'])
@login_required
def close_offense():
    data = request.json
    offense_ids = data.get('offense_ids')
    reason_id = data.get('reason_id')
    note = data.get('note')
    user_id = data.get('user_id')

    logging.info(f"Intentando cerrar ofensas: {offense_ids}, Razón de cierre: {reason_id}, Usuario: {user_id}")

    if not offense_ids or not reason_id:
        return jsonify({"error": "Se requiere IDs de ofensas y razón de cierre"}), 400

    failed_offenses = [] 

    for offense_id in offense_ids:
        url_closing = f"{QRADAR_OFFENSES}/{offense_id}?closing_reason_id={reason_id}&status=CLOSED"
        response = requests.post(url_closing, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)

        if response.status_code != 200:
            failed_offenses.append({
                "offense_id": offense_id, 
                "error": f"Error al cerrar la ofensa con ID {offense_id}. Código de estado: {response.status_code}. Respuesta: {response.text}"
            })
            logging.error(f'Error al cerrar ofensa {offense_id}: {response.status_code} - {response.text}')
            
            continue  
        logging.info(f'Ofensa {offense_id} cerrada correctamente.')

        if note:
            url_notas = f"{QRADAR_OFFENSES}/{offense_id}/notes?note_text={note}"
            response_note = requests.post(url_notas, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
            if response_note.status_code != 201:
                failed_offenses.append({
                    "offense_id": offense_id, 
                    "error": f"Error al agregar la nota a la Ofensa {offense_id}. Código de estado: {response_note.status_code}. Respuesta: {response_note.text}"
                })
                logging.error(f'Error al agregar la nota a la ofensa {offense_id}: {response_note.status_code} - {response_note.text}')
            else:
                logging.info(f'Nota agregada correctamente a la ofensa {offense_id}.')

        if user_id:
            url_assigned = f"{QRADAR_OFFENSES}/{offense_id}?assigned_to={user_id}"
            response = requests.post(url_assigned, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
            if response.status_code != 200:
                print(f"Error al asignar la Ofensa {offense_id} a {user_id}. Código de estado: {response.status_code}")
                print(f"Respuesta de QRadar: {response.text}")
                return jsonify({"error": f"No se pudo asignar la Ofensa {offense_id} a {user_id}"}), 500

            logging.info(f'Ofensa {offense_id} asignada correctamente al usuario {user_id}.')
            
    if failed_offenses:
        logging.error(f'Algunas ofensas no se pudieron cerrar: {failed_offenses}')
        return jsonify({
            "error": "Algunas ofensas no se pudieron cerrar",
            "failed_offenses": failed_offenses
        }), 500
    logging.info(f'Se han cerrado correctamente {len(offense_ids)} ofensas.')
    return jsonify({"message": f"Se han cerrado correctamente {len(offense_ids)} ofensas"})


# AGREGAR RAZON
@app.route('/api/agregar_razon', methods=['POST'])
@login_required
def add_closing_reason():
    data = request.json
    reason = data.get('reason')
    logging.info(f'Intentando agregar una razón de cierre: {reason}')
    if not reason:
        logging.warning('La razón de cierre es requerida.')
        return jsonify({"error": "La razón de cierre es requerida"}), 400

    print(reason)
    url_agregar_ofensa = f"{QRADAR_OFFENSES_CLOSING_REASONS}?reason={reason}"
    response = requests.post(url_agregar_ofensa, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS2, verify=False)
    
    if response.status_code == 201:
        logging.info(f'Razón de cierre agregada correctamente: {reason}')
        return jsonify({"message": "Razón de cierre agregada correctamente"}), 200
    else:
        logging.error(f'Error al agregar la razón de cierre: {response.status_code} - {response.text}')
        return jsonify({"error": "No se pudo agregar la razón de cierre", "details": response.json()}), response.status_code
    

# OCULTAR OFENSAS
@app.route('/api/ocultar_ofensa', methods=['POST'])
@login_required
def ocultar_ofensa():
    data = request.json
    offense_ids = data.get('offense_ids')
    note = data.get('note') 

    logging.info(f'Intentando ocultar ofensas: {offense_ids}, Nota: {note}')

    if not offense_ids:
        logging.warning('Se requiere al menos un ID de ofensa para ocultar.')
        return jsonify({"error": "Se requiere al menos un ID de ofensa para ocultar"}), 400

    for offense_id in offense_ids:
        url_hide = f"{QRADAR_OFFENSES}/{offense_id}?status=HIDDEN"
        response = requests.post(url_hide, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)

        if response.status_code != 200:
            return jsonify({"error": f"No se pudo ocultar la ofensa con ID {offense_id}"}), 500

        if note:
            url_notas = f"{QRADAR_OFFENSES}/{offense_id}/notes?note_text={note}"
            response_note = requests.post(url_notas, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
            if response_note.status_code != 201:
                logging.error(f'Error al agregar la nota a la ofensa {offense_id}. Código de estado: {response_note.status_code}')
                logging.error(f'Respuesta de QRadar: {response_note.text}')
                return jsonify({"error": f"No se pudo agregar la nota a la ofensa con ID {offense_id}"}), 500
            logging.info(f'Nota agregada correctamente a la ofensa {offense_id}.')

    return jsonify({"message": f"Se han ocultado correctamente {len(offense_ids)} ofensas"})


# AGREGAR NOTA
@app.route('/api/agregar_nota', methods=['POST'])
@login_required
def agregar_nota():
    data = request.json
    offense_ids = data.get('offense_ids')
    note = data.get('note')

    logging.info(f'Intentando agregar una nota a las ofensas: {offense_ids}, Nota: {note}')


    if not offense_ids or not note:
        logging.warning('Se requiere IDs de ofensas y una nota para agregar.')
        return jsonify({"error": "Se requiere IDs de ofensas y una nota"}), 400

    for offense_id in offense_ids:
        url_notas = f"{QRADAR_OFFENSES}/{offense_id}/notes?note_text={note}"
        response = requests.post(url_notas, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)

        if response.status_code != 200:
            logging.error(f'Error al agregar la nota a la ofensa {offense_id}. Código de estado: {response.status_code}')
            logging.error(f'Respuesta de QRadar: {response.text}')
            return jsonify({"error": f"No se pudo agregar la nota a la ofensa con ID {offense_id}"}), 500
        logging.info(f'Nota agregada correctamente a la ofensa {offense_id}.')
    return jsonify({"message": f"Se han agregado notas a {len(offense_ids)} ofensas"})



# ASIGNAR OFENSAS Y AGREGAR NOTA
@app.route('/api/asignar', methods=['POST'])
@login_required
def asignar_ofensa():
    data = request.json
    offense_ids = data.get('offense_ids')
    user_id = data.get('user_id')
    note = data.get('note')  

    logging.info(f'Intentando asignar ofensas: {offense_ids}, Usuario: {user_id}, Nota: {note}')

    if not offense_ids or not user_id:
        logging.warning('Faltan los IDs de ofensa o el ID de usuario.')
        return jsonify({"error": "Se requiere IDs de ofensas y un ID de usuario para la asignación"}), 400

    for offense_id in offense_ids:
        url_assigned = f"{QRADAR_OFFENSES}/{offense_id}?assigned_to={user_id}"
        response = requests.post(url_assigned, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)

        if response.status_code != 200:
            logging.error(f"Error al asignar la Ofensa {offense_id} a {user_id}. Código de estado: {response.status_code}")
            logging.error(f"Respuesta de QRadar: {response.text}")
            print(f"Error al asignar la Ofensa {offense_id} a {user_id}. Código de estado: {response.status_code}")
            print(f"Respuesta de QRadar: {response.text}")
            return jsonify({"error": f"No se pudo asignar la Ofensa {offense_id} a {user_id}"}), 500
        logging.info(f'Ofensa {offense_id} asignada correctamente al usuario {user_id}.')

        if note:
            url_notas = f"{QRADAR_OFFENSES}/{offense_id}/notes?note_text={note}"
            response_note = requests.post(url_notas, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
            
            if response_note.status_code != 200:
                logging.error(f'Error al agregar la nota a la ofensa {offense_id}. Código de estado: {response_note.status_code}')
                logging.error(f'Respuesta de QRadar: {response_note.text}')
                print(f"Error al agregar la nota a la Ofensa {offense_id}. Código de estado: {response_note.status_code}")
                print(f"Respuesta de QRadar: {response_note.text}")
                return jsonify({"error": f"No se pudo agregar la nota a la Ofensa {offense_id}"}), 500
            logging.info(f'Nota agregada correctamente a la ofensa {offense_id}.')

    return jsonify({"message": f"Se han asignado correctamente {len(offense_ids)} ofensas al usuario {user_id}"}), 200




def timestamp_to_str(ts):
    try:
        ts_num = float(ts)
        if ts_num > 0:
            return datetime.utcfromtimestamp(ts_num).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, OSError):
        pass
    return 'N/A'



# OBTENER EVENTOS
@app.route('/api/obtener_eventos', methods=['POST'])
@login_required
def obtener_eventos():
    # Recibir datos del formulario
    offense_id = request.form.get('codigo_ofensa')
    fecha_inicio = request.form.get('fecha_inicio')
    hora_inicio = request.form.get('hora_inicio')
    fecha_fin = request.form.get('fecha_fin')
    hora_fin = request.form.get('hora_fin')

    if not offense_id:
        return jsonify({"error": "Se requiere el offense_id para obtener los eventos"}), 400
    
    # Combinar fecha y hora
    fecha_hora_inicio = f"{fecha_inicio} {hora_inicio}"  # "YYYY-MM-DD HH:MM"
    fecha_hora_fin = f"{fecha_fin} {hora_fin}"  # "YYYY-MM-DD HH:MM"

    try:
        fecha_inicio_dt = datetime.strptime(fecha_hora_inicio, '%Y-%m-%d %H:%M')  # Formato combinado
        fecha_fin_dt = datetime.strptime(fecha_hora_fin, '%Y-%m-%d %H:%M')  # Formato combinado
    except ValueError:
        return jsonify({"error": "Formato de fecha o hora inválido. Debe ser 'YYYY-MM-DD HH:MM'"}), 400


    fecha_inicio_ms = int(fecha_inicio_dt.timestamp()) * 1000  # Convertir a milisegundos
    fecha_fin_ms = int(fecha_fin_dt.timestamp()) * 1000  # Convertir a milisegundos


    query_expression = f"SELECT starttime, sourceip, destinationip, username, payload " \
                        f"FROM events WHERE INOFFENSE('{offense_id}') LIMIT 100 " \
                        f"START '{fecha_inicio_ms}' STOP '{fecha_fin_ms}'"

    search_url = f"{QRADAR_SEARCHES}?query_expression={query_expression}"
    response_search = requests.post(search_url, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)

    data_search = response_search.json()

    
    data_search_id = data_search.get('search_id')

    search_status_url = f"{QRADAR_SEARCHES}/{data_search_id}"

    MAX_WAIT_TIME = 120  
    CHECK_INTERVAL = 5 
    elapsed_time = 0

    while elapsed_time < MAX_WAIT_TIME:
        search_status_response = requests.get(search_status_url, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
        
        # Verificar si hubo un error en la respuesta
        if not search_status_response.ok:
            return render_template('error.html', error_message="Error al consultar el estado de la búsqueda en QRadar")

        data_status = search_status_response.json()
        data_status_search = data_status.get('status')

        if data_status_search == 'COMPLETED':
            break
        elif data_status_search == 'EXECUTE' or data_status_search == 'SORTING':
            # Esperar un poco más si el estado es 'EXECUTE' o 'SORTING'
            time.sleep(CHECK_INTERVAL)
            elapsed_time += CHECK_INTERVAL
        else:
            # Mensaje de error más detallado para ayudar a depurar
            return render_template('error.html', error_message=f"La búsqueda no se completó. Estado actual: {data_status_search}")

    # Si alcanzamos el tiempo máximo de espera
    if elapsed_time >= MAX_WAIT_TIME:
        # Mostrar el error en la web en lugar de JSON
        return render_template('error.html', error_message="La búsqueda excedió el tiempo máximo de espera")

    # Obtener los resultados de la búsqueda si la búsqueda se completó
    search_status_result = f"{QRADAR_SEARCHES}/{data_search_id}/results"
    search_url_result = requests.get(search_status_result, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)
    
    # Verificar si hubo un error en la respuesta
    if not search_url_result.ok:
        return render_template('error.html', error_message="Error al obtener los resultados de la búsqueda en QRadar")
    
    data_result_event = search_url_result.json()

    events = []
    if "events" in data_result_event:
        for idx, data_status_result in enumerate(data_result_event["events"]):

            data_payload_base64 = data_status_result.get("payload", "")
            data_payload_bytes = base64.b64decode(data_payload_base64)
            data_payload_text = data_payload_bytes.decode('utf-8')

            pattern = re.compile(r'<\d+>')  # Limpiar los datos del payload
            data_payload_text_cleaned = re.sub(pattern, '', data_payload_text)

            events.append({
                "starttime": data_status_result.get("starttime"),
                "sourceip": data_status_result.get("sourceip"),
                "destinationip": data_status_result.get("destinationip"),
                "username": data_status_result.get("username"),
                "payload": data_payload_text_cleaned
            })
    else:
        return render_template('error.html', error_message="No se encontraron eventos para la búsqueda.")

    url_ofensa = f"{QRADAR_OFFENSES}/{offense_id}"
    response_ofensa = requests.get(url_ofensa, auth=QRADAR_AUTH, headers=QRADAR_REQUEST_HEADERS, verify=False)

    if response_ofensa.status_code != 200:
        return jsonify({"error": "No se pudo obtener los datos de la ofensa"}), 500

    data_ofensa = response_ofensa.json()

    ofensa = []
    ofensa.append({
        "id": data_ofensa.get("id"),
        "descripcion": data_ofensa.get("description", "").replace('\n', ' '),
        "rules": data_ofensa.get("rules", []),
        "magnitude": str(data_ofensa.get("magnitude", "-")),
        "severity": str(data_ofensa.get("severity", "-")),
        "relevance": str(data_ofensa.get("relevance", "-")),
        "credibility": str(data_ofensa.get("credibility", "-")),
        "origen": data_ofensa.get("offense_source", "-"),
        "fecha_inicio": timestamp_to_str(data_ofensa.get("start_time", 0)),
        "fecha_fin": timestamp_to_str(data_ofensa.get("last_updated_time", 0)),
        "eventos": data_ofensa.get("event_count", 0),
        "destination_networks": data_ofensa.get("destination_networks", []),
        "log_sources": data_ofensa.get("log_sources", []),
        "categorias": data_ofensa.get("categories", []),
        "status": data_ofensa.get("status", []),
    })

    print(ofensa)

    return render_template('ofensas.html', events=events, ofensa=ofensa)  
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
