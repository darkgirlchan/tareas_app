import pyodbc
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
from flask import flash
from flask import Flask, render_template, request, redirect, url_for

# Configuración de la base de datos
conn = pyodbc.connect('DRIVER={SQL Server};SERVER=DARKSYSTEM;DATABASE=tareas_app;Trusted_Connection=yes;')
cursor = conn.cursor()

# Crear la aplicación Flask
app = Flask(__name__)
app.secret_key = 'mi_clave_secreta'  # Cambia esto por una clave secreta para la sesión

# Ruta para la página de inicio
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# Ruta para el registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Recoger datos del formulario
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        fecha_nacimiento = request.form['fecha_nacimiento']

        # Verificar si el email ya está registrado en la base de datos
        cursor.execute("SELECT * FROM usuarios WHERE email=?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            return "El correo electrónico ya está registrado."

        # Generar el hash de la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Asegúrate de que el campo en la base de datos sea lo suficientemente largo
        cursor.execute("INSERT INTO usuarios (nombre, email, password,fecha_nacimiento) VALUES (?, ?, ?,?)", (nombre, email, hashed_password.decode('utf-8'),fecha_nacimiento))
        conn.commit()

        return redirect(url_for('login'))
    return render_template('register.html')

# Ruta para el inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Recoger datos del formulario
        email = request.form['email']
        password = request.form['password']

        # Buscar al usuario en la base de datos
        cursor.execute("SELECT * FROM usuarios WHERE email=?", (email,))
        user = cursor.fetchone()

        if user:
            # Comparar la contraseña ingresada con el hash almacenado
            if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):  # user[3] es el campo de la contraseña hashada
                session['user_id'] = user[0]  # Almacenar el ID de usuario en la sesión
                return redirect(url_for('dashboard'))  # Redirigir a la página de tareas

        return "Email o contraseña incorrectos", 401  # Mensaje de error si el login falla

    return render_template('login.html')  # Página de login


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Obtener las tareas del usuario logueado
    cursor.execute("SELECT * FROM tareas WHERE usuario_id = ?", (session['user_id'],))
    tareas = cursor.fetchall()  # Obtener todas las tareas del usuario
    
    return render_template('dashboard.html', tareas=tareas)
@app.route('/crear_tarea', methods=['POST'])
def crear_tarea():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    titulo = request.form['titulo']
    descripcion = request.form['descripcion']
    estado = 'Pendiente'
    usuario_id = session['user_id']
    email_asignado = request.form['email_asignado']

    # Buscar el ID del usuario asignado por su correo electrónico
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email_asignado,))
    resultado = cursor.fetchone()

    if resultado:
    # Si el correo existe, asignar el ID del usuario encontrado
        asignado_a = resultado[0]
        usuario_id = asignado_a  # Se actualiza el creador de la tarea al asignado
    else:
        # Si el correo no existe
        if email_asignado == "":
            # Si no se proporcionó un correo, asignar al usuario en sesión
            asignado_a = usuario_id
        else:
            # Si se proporcionó un correo, pero no existe en la base de datos
            flash("El correo no existe. No se puede asignar la tarea.", "error")
            return redirect(url_for('dashboard'))

    cursor.execute(
        "INSERT INTO tareas (titulo, descripcion, estado, usuario_id, asignado_a) VALUES (?, ?, ?, ?, ?)",
        (titulo, descripcion, estado, usuario_id, asignado_a)
    )
    conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/cambiar_estado/<int:tarea_id>', methods=['POST'])
def cambiar_estado(tarea_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Obtener el nuevo estado desde el formulario
    nuevo_estado = request.form['estado']
    
    # Actualizar el estado de la tarea en la base de datos
    cursor.execute("UPDATE tareas SET estado = ? WHERE id = ?", (nuevo_estado, tarea_id))
    conn.commit()

    # Verificación de la actualización
    print(f"Tarea {tarea_id} cambiada a estado {nuevo_estado}")

    return redirect(url_for('dashboard'))

@app.route('/eliminar_tarea/<int:tarea_id>', methods=['POST'])
def eliminar_tarea(tarea_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Eliminar la tarea de la base de datos
    cursor.execute("DELETE FROM tareas WHERE id = ?", (tarea_id,))
    conn.commit()

    return redirect(url_for('dashboard'))  # Redirigir al dashboard

@app.route('/recuperar', methods=['POST', 'GET'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = request.form.get('email')
        fecha_nacimiento = request.form.get('fecha_nacimiento')

        # Consulta SQL para buscar al usuario
        cursor = conn.cursor()
        query = """
            SELECT id FROM usuarios 
            WHERE email = ? AND fecha_nacimiento = ?
        """
        cursor.execute(query, (email, fecha_nacimiento))
        usuario = cursor.fetchone()

        if usuario:
            # `usuario[0]` es el id del usuario encontrado
            return redirect(url_for('restablecer_contrasena', usuario_id=usuario[0]))
        else:
            # Muestra un mensaje de error
            return render_template('recuperar_contrasena.html', error="Datos incorrectos")

    return render_template('recuperar_contrasena.html')

@app.route('/restablecer_contrasena/<int:usuario_id>', methods=['POST', 'GET'])
def restablecer_contrasena(usuario_id):
    if request.method == 'POST':
        nueva_contrasena = request.form['nueva_contrasena']

        # Hash opcional para la contraseña
        hashed_password = bcrypt.hashpw(nueva_contrasena.encode('utf-8'), bcrypt.gensalt())

        # Actualización de la contraseña en la base de datos
        cursor = conn.cursor()
        query = """
            UPDATE usuarios
            SET password = ?
            WHERE id = ?
        """
        cursor.execute(query, (hashed_password, usuario_id))
        conn.commit()

        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html', usuario_id=usuario_id)

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Eliminar el ID de la sesión
    return redirect(url_for('login'))

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)
