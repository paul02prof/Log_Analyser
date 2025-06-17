from fastapi import FastAPI, Request,Form
import sqlite3
import uvicorn
import json
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import subprocess





app = FastAPI()

# Autoriser CORS pour que le front puisse accéder à l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # à restreindre en prod
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def lire_index():
    return FileResponse("static/index.html")

@app.get("/logs_page")
def logs_page():
    return FileResponse("static/log.html")

@app.get("/dash_admin")
def logs_page():
    return FileResponse("static/dash_admin.html")

@app.get("/update_user")
def logs_page():
    return FileResponse("static/update_user.html")


@app.get("/logs_user")
def logs_page():
    return FileResponse("static/log_user.html")

@app.get("/add_host")
def logs_page():
    return FileResponse("static/add_host.html")

@app.get("/add_user")
def lire_index():
    return FileResponse("static/add_user.html")

@app.get("/add_user_admin")
def lire_index():
    return FileResponse("static/add_user_admin.html")


@app.get("/sign_in")
def lire_index():
    return FileResponse("static/signin.html")


@app.get("/dashboard")
def lire_index():
    return FileResponse("static/user_dash.html")


@app.get("/filter/type")
def get_types():
    conn = sqlite3.connect("log_db.db")
    c = conn.cursor()
    c.execute("SELECT name_type FROM Type_log")
    types = [row[0] for row in c.fetchall()]
    conn.close()
    return types

@app.get("/filter/severity")
def get_severities():
    conn = sqlite3.connect("log_db.db")
    c = conn.cursor()
    c.execute("SELECT name_sev FROM Severity")
    severities = [row[0] for row in c.fetchall()]
    conn.close()
    return severities

@app.get("/filter/host")
def get_hosts():
    conn = sqlite3.connect("log_db.db")
    c = conn.cursor()
    c.execute("SELECT DISTINCT id_host FROM log")
    hosts = [str(row[0]) for row in c.fetchall()]
    conn.close()
    return hosts

@app.get("/filter/process")
def get_hosts():
    conn = sqlite3.connect("log_db.db")
    c = conn.cursor()
    c.execute("SELECT DISTINCT process_nom FROM Log")
    process = [str(row[0]) for row in c.fetchall()]
    conn.close()
    return process

@app.get("/categories")
def get_categories():
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name_cat FROM Category")
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

@app.get("/users_id")
def get_categories():
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id_user FROM User")
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

@app.post("/add_user")
def add_user(nom: str = Form(...), category: str = Form(...), password:str= Form(...)):
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO User (nom, category, password) VALUES (?, ?, ?)", (nom, category, password))
    conn.commit()
    conn.close()
    return {"message": "Utilisateur ajouté avec succès"}


@app.post("/add_user_admin")
def add_user(nom: str = Form(...), category: str = Form(...), password:str= Form(...)):
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO User (nom, category, password) VALUES (?, ?, ?)", (nom, category, password))
    conn.commit()
    conn.close()
    return {"message": "Utilisateur ajouté avec succès"}

@app.post("/update_user")
def update_user( id_user: int = Form(...),nom: str = Form(...),password: str = Form(...),category: str = Form(...)
):
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE User
        SET nom = ?, password = ?, category = ?
        WHERE id_user = ?
    """, (nom, password, category, id_user))

    conn.commit()
    conn.close()

    return {"message": f"Utilisateur {id_user} mis à jour avec succès."}

@app.post("/signin")
async def signin(request: Request):
    data = await request.json()
    nom = data.get("nom")
    password = data.get("password")

    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id_user, nom ,category FROM User WHERE nom=? AND password=?", (nom, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return {"success": True,"id_user": user[0], "nom": user[1], "category":user[2]}
    else:
        return JSONResponse(content={"success": False}, status_code=401)



@app.get("/all_logs")
def get_logs():
    conn = sqlite3.connect("log_db.db")
    c = conn.cursor()
    c.execute("""
        SELECT id_log, date, time, message,source, pid,type, process_nom,severity, id_host FROM Log
    """)
    rows = c.fetchall()
    conn.close()

    logs = [
        {
            "id_log": row[0],
            "date": row[1],
            "time": row[2],
            "message": row[3],
            "source":row[4],
            "pid": row[5],
            "type": row[6],
            "process_nom": row[7],
            "severity": row[8],
            "id_host": row[9]
        }
        for row in rows
    ]
    return logs

@app.get("/all_users")
def get_logs():
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id_user, nom,category FROM User ")
    users = [{"id_user": row[0], "nom": row[1], "category": row[2]} for row in cursor.fetchall()]
    conn.close()
    return users

@app.get("/all_hosts")
def get_hosts():
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id_host, ip_address FROM Host ")
    hosts = [{"id_host": row[0], "ip_address": row[1]} for row in cursor.fetchall()]
    conn.close()
    return hosts

@app.get("/user/{id_user}")
def get_user(id_user: int):
    conn = sqlite3.connect("log_db.db")
    conn.row_factory = sqlite3.Row  # Pour avoir les colonnes avec des noms
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM User WHERE id_user = ?", (id_user,))
    user = cursor.fetchone()

    conn.close()

    if user:
        return {
            "id_user": user["id_user"],
            "nom": user["nom"],
            "password": user["password"],
            "category": user["category"]
        }
    else:
        return JSONResponse(status_code=404, content={"message": "Utilisateur non trouvé."})


@app.get("/logs/{id_user}")
def get_user_logs(id_user: int):
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()

    query = """
        SELECT Log.id_log, Log.date, Log.time, Log.message,Log.source,Log.pid ,
               Log.type,Log.process_nom ,Log.severity,Log.id_host
        FROM Log
        JOIN Host ON Log.id_host = Host.id_host
        WHERE Host.id_user = ?
    """
    cursor.execute(query, (id_user,))
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id_log": row[0],
            "date": row[1],
            "time": row[2],
            "message": row[3],
            "source":row[4],
            "pid": row[5],
            "type": row[6],
            "process_nom": row[7],
            "severity": row[8],
            "id_host": row[9]

        })

    return JSONResponse(content=logs)

@app.get("/filter/hosts/{id_user}")
def get_hosts_for_user(id_user: int):
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id_host FROM Host WHERE id_user = ?", (id_user,))
    hosts = [row[0] for row in cursor.fetchall()]
    conn.close()
    return hosts


def insert_json(log_json):
    conn = sqlite3.connect("log_db.db")
    c = conn.cursor()
    for data in log_json:
        c.execute("SELECT id_host FROM host WHERE ip_address = ?", (data.get("ip_machine"),))
        result = c.fetchone()
        id_host = result[0]

        c.execute("INSERT INTO Log (date,time,message,type,severity,id_host,source,PID,service,nom_machine,process_nom )VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                  (data.get("date"), data.get("heure"), data.get("message"), data.get("categorie_log"), data.get("severite"),
                   id_host,data.get("source"),data.get("pid"), data.get("service_systemd"),data.get("nom_machine"),
                   data.get("utilisateur_nom")
                   ))

    conn.commit()
    conn.close()

@app.post("/upload_json")
async def upload_json(request: Request):
    try:
        data = await request.json()
        insert_json(data)
        return {"status": "success", "message": "JSON reçu et inséré"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/add_host")
async def add_host(request: Request):
    data = await request.json()
    ip = data.get("ip_address")
    id_user = data.get("id_user")

    # Test de connectivité via ping
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            return {"success": False, "message": f"Adresse IP injoignable : {ip}"}
    except Exception as e:
        return {"success": False, "message": f"Erreur lors du ping : {str(e)}"}

    # Insertion dans la base
    try:
        conn = sqlite3.connect("log_db.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Host (ip_address, id_user) VALUES (?, ?)", (ip, id_user))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "message": f"Erreur base de données : {str(e)}"}


@app.get("/get_hosts/{id_user}")
def get_hosts(id_user: int):
    conn = sqlite3.connect("log_db.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id_host, ip_address FROM Host WHERE id_user = ?", (id_user,))
    hosts = [{"id_host": row[0], "ip_address": row[1]} for row in cursor.fetchall()]
    conn.close()
    return hosts

@app.delete("/delete_host/{id_host}")
def delete_host(id_host: int):
    try:
        conn = sqlite3.connect("log_db.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Host WHERE id_host = ?", (id_host,))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "message": str(e)}


@app.delete("/delete_user/{id_user}")
def delete_host(id_user: int):
    try:
        conn = sqlite3.connect("log_db.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM User WHERE id_user = ?", (id_user,))
        cursor.execute("DELETE FROM Host WHERE id_user = ?", (id_user,))
        cursor.execute("DELETE FROM Log WHERE id_host in (select id_host from host where id_user=?)", (id_user,))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "message": str(e)}


if __name__ == "__main__":
    uvicorn.run("serveur:app", host="127.0.0.1", port=8000, reload=True)
