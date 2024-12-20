import pyodbc
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
from flask import flash
import re
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    def validar_contraseña(password):
        """
        Valida que la contraseña cumpla con los siguientes requisitos:
        - Al menos 8 caracteres
        - Al menos una letra mayúscula
        - Al menos una letra minúscula
        - Al menos un número
        - Al menos un símbolo
        """
        if len(password) < 8:
            return "La contraseña debe tener al menos 8 caracteres."
        if not re.search(r"[A-Z]", password):
            return "La contraseña debe tener al menos una letra mayúscula."
        if not re.search(r"[a-z]", password):
            return "La contraseña debe tener al menos una letra minúscula."
        if not re.search(r"\d", password):
            return "La contraseña debe tener al menos un número."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return "La contraseña debe tener al menos un símbolo especial."
        return None

    if request.method == 'POST':
        # Recoger datos del formulario
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        fecha_nacimiento = request.form['fecha_nacimiento']

        # Validar la contraseña
        mensaje_error = validar_contraseña(password)
        if mensaje_error:
            return render_template('register.html', mensaje_error=mensaje_error)

        # Verificar si el email ya está registrado en la base de datos
        cursor.execute("SELECT * FROM usuarios WHERE email=?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            return render_template('register.html', mensaje_error="El correo electrónico ya está registrado.")

        # Generar el hash de la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insertar datos en la base de datos
        cursor.execute(
            "INSERT INTO usuarios (nombre, email, password, fecha_nacimiento) VALUES (?, ?, ?, ?)",
            (nombre, email, hashed_password.decode('utf-8'), fecha_nacimiento)
        )
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
    
    # Obtener el nombre del usuario logueado
    cursor.execute("SELECT nombre FROM usuarios WHERE id = ?", (session['user_id'],))
    usuario = cursor.fetchone()
    
    # Si no se encuentra el usuario, redirigir al login
    if not usuario:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for('login'))

    nombre_usuario = usuario[0]  # El nombre del usuario
    
    # Obtener las tareas del usuario logueado
    cursor.execute("SELECT * FROM tareas WHERE usuario_id = ?", (session['user_id'],))
    tareas = cursor.fetchall()  # Obtener todas las tareas del usuario
    
    return render_template('dashboard.html', tareas=tareas, nombre_usuario=nombre_usuario)

@app.route('/crear_tarea', methods=['POST'])
def crear_tarea():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Recoger datos del formulario
    titulo = request.form['titulo']
    descripcion = request.form['descripcion']
    prioridad = request.form['prioridad']
    fecha_entrega = request.form['fecha_entrega']  # Nuevo campo
    estado = 'Pendiente'
    usuario_id = session['user_id']
    email_asignado = request.form['email_asignado']

    # Buscar el ID del usuario asignado por su correo electrónico
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email_asignado,))
    resultado = cursor.fetchone()
   

    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email_asignado,))
    resultado = cursor.fetchone()

    if resultado:
        asignado_a = resultado[0]
        usuario_id = asignado_a  # Se actualiza el creador de la tarea al asignado
    else:
        # Si el correo no existe
        if email_asignado == "":
            flash("El correo no existe. No se puede asignar la tarea.", "error")
            return redirect(url_for('dashboard'))

    # Insertar la nueva tarea con prioridad y fecha de entrega
    cursor.execute(
        """
        INSERT INTO tareas (titulo, descripcion, estado, usuario_id, asignado_a, prioridad, fecha_entrega)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (titulo, descripcion, estado, usuario_id, asignado_a, prioridad, fecha_entrega)
    )
    conn.commit()

    flash("Tarea creada exitosamente.", "success")
    return redirect(url_for('dashboard'))

@app.route('/editar_tarea/<int:tarea_id>', methods=['GET'])
def editar_tarea(tarea_id):
    cursor.execute("SELECT id, titulo, descripcion, fecha_entrega FROM tareas WHERE id = ?", (tarea_id,))
    tarea = cursor.fetchone()
    
    if not tarea:
        flash("Tarea no encontrada.", "error")
        return redirect(url_for('dashboard'))
    
    return render_template('editar_tarea.html', tarea=tarea)
@app.route('/guardar_tarea_editada/<int:tarea_id>', methods=['POST'])
def guardar_tarea_editada(tarea_id):
    # Recoger los datos del formulario
    titulo = request.form['titulo']
    descripcion = request.form['descripcion']
    fecha_entrega = request.form['fecha_entrega']

    # Actualizar en la base de datos
    cursor.execute("""
        UPDATE tareas 
        SET titulo = ?, descripcion = ?, fecha_entrega = ?
        WHERE id = ?
    """, (titulo, descripcion, fecha_entrega, tarea_id))
    conn.commit()

    flash("Tarea actualizada con éxito.", "success")
    return redirect(url_for('dashboard'))


@app.route('/cambiar_prioridad/<int:tarea_id>', methods=['POST'])
def cambiar_prioridad(tarea_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Obtener la nueva prioridad desde el formulario
    nueva_prioridad = request.form['prioridad']

    # Realizar la actualización en la base de datos
    cursor.execute("UPDATE tareas SET prioridad = ? WHERE id = ?", (nueva_prioridad, tarea_id))
    conn.commit()

    # Verificar la actualización (opcional, para depuración)
    cursor.execute("SELECT prioridad FROM tareas WHERE id = ?", (tarea_id,))
    nueva_prioridad_db = cursor.fetchone()[0]
    print(f"Prioridad actualizada a: {nueva_prioridad_db}")

    # Flash para confirmar que la prioridad se ha actualizado
    flash('La prioridad de la tarea ha sido actualizada.', 'success')

    # Redirigir a la página del dashboard
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
    def validar_contraseña(password):
        """
        Valida que la contraseña cumpla con los siguientes requisitos:
        - Al menos 8 caracteres
        - Al menos una letra mayúscula
        - Al menos una letra minúscula
        - Al menos un número
        - Al menos un símbolo
        """
        if len(password) < 8:
            return "La contraseña debe tener al menos 8 caracteres."
        if not re.search(r"[A-Z]", password):
            return "La contraseña debe tener al menos una letra mayúscula."
        if not re.search(r"[a-z]", password):
            return "La contraseña debe tener al menos una letra minúscula."
        if not re.search(r"\d", password):
            return "La contraseña debe tener al menos un número."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return "La contraseña debe tener al menos un símbolo."
        return None

    if request.method == 'POST':
        nueva_contrasena = request.form['nueva_contrasena']

        # Validar la nueva contraseña
        mensaje_error = validar_contraseña(nueva_contrasena)
        if mensaje_error:
            return render_template('restablecer_contrasena.html', usuario_id=usuario_id, mensaje_error=mensaje_error)

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


@app.route('/editar-datos-usuario', methods=['GET', 'POST'])
def editar_datos_usuario():
    # Acceder al usuario actual desde la sesión
    usuario_id = session['user_id']
    
    cursor = conn.cursor()
    
    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nuevo_email = request.form['email']
        
        if nuevo_nombre and nuevo_email:
            query = """
                UPDATE usuarios
                SET nombre = ?, email = ?
                WHERE id = ?
            """
            cursor.execute(query, (nuevo_nombre, nuevo_email, usuario_id))
            conn.commit()
            
            flash('Datos del usuario actualizados correctamente.', 'success')
            return redirect(url_for('editar_datos_usuario'))
        else:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('editar_datos_usuario'))
    
    # Obtener los datos actuales del usuario para prellenar el formulario
    query = """
        SELECT nombre, email FROM usuarios WHERE id = ?
    """
    cursor.execute(query, (usuario_id,))
    usuario = cursor.fetchone()

    return render_template('editar_datos_usuario.html', usuario=usuario)
    
@app.route('/logout')
def logout():
    # Lógica para cerrar sesión
    session.pop('user_id', None)
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)
