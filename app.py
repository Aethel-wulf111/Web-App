from flask import Flask, render_template, Blueprint, request, current_app, send_file
from flask_fontawesome import FontAwesome
from werkzeug.utils import secure_filename
from scripts.static_create_files_to_analyse import Extract_informations
from scripts.delete_files_created_before import delete_all
from scripts.signature_analysis import start_signature_analysis
from scripts.machine_learning_test import start_ml_analysis
from scripts.obsufuctions import Obsufuctions_Analysis
from scripts.solution_existante import solution_deja_existante
import os, time, datetime
import threading
from scripts.behav import behav_analysis
from scripts.pdf import generate_report, get_pdf


app = Flask(__name__)
UPLOAD_FOLDER = '.\\uploads'
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

#app.register_blueprint(app, url_prefix="/app")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/results")
def results():
    return render_template("results.html")

@app.route("/full_scans")
def full_results():
    return render_template("full_scan.html")

@app.route("/download_report")
def full_scans():
    return send_file(get_pdf(), as_attachment=True)

# Create a lock object
lock = threading.Lock()

@app.route('/upload', methods = ['POST'])  
def upload():
    # Acquire the lock to ensure mutual exclusion
    lock.acquire()
    try:
        data = []
        files = request.files.getlist("file")
        data = {}
        desc = {}
        details = []
        for f in files:
            filename = f.filename
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # EXTRACT THE INFORMATIONS
        now = datetime.datetime.now()
        s = Extract_informations(filename)
        for i in s:
            details.append(i)
        details.append(str(now))
        # ANALYSIS
        data["Signature"] = start_signature_analysis(filename)
        desc["Signature"] = "Detect the ransomware by his signature in our datasets of ransomwares files"
        # Analyse prediction only file systeme
        try:
            data["ML"] = start_ml_analysis(filename)
            desc["ML"] = "Detect the ransomware by machine learning using random forest with a datasets."
        except IndexError:
            data["ML"] = True
            desc["ML"] = "Detect the ransomware by machine learning using random forest with a datasets."
        # obsufuctions
        data["Entropy"],data["Encryption Algorithmes"],data["Anti debugging detection"],data["Anti vms detection"] = Obsufuctions_Analysis(filename)
        desc["Entropy"] = "Detect the ransomware by entropy"
        desc["Encryption Algorithmes"] = "Detect the ransomware by Encryption Algorithmes"
        desc["Anti debugging detection"] = "Detect the ransomware by Anti debugging"
        desc["Anti vms detection"] = "Detect the ransomware by Anti Virtual Machines"
        # Behaviour analysis
        data["Behaviour Detection"], desc["Behaviour_Detection"], familly = behav_analysis(filename)
        # Solution deja existe
        ss = []
        data["Intezer API"], data["Scanii API"], ss = solution_deja_existante(filename)
        try :
            if len(ss) == 2:
                for i in range(len(ss[0])):
                    data[ss[0][i]] = ss[1][i]
        except TypeError:
            data["Smart analysis"] = ss
        # Generate the report
        path_to_pdf = generate_report(data,s,familly,filename)
        # DELETE THE EXTRACT INFO + UPLOADS FILES
        delete_all(filename)
        send_file(path_to_pdf, as_attachment=True)
        return render_template("results.html", data=data, desc=desc, details=details, path_to_pdf=path_to_pdf)
    finally:
        # Release the lock to allow other threads to acquire it
        lock.release()

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True,port=8000)

#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif 