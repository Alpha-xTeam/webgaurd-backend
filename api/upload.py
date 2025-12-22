from flask import Blueprint, request, jsonify, current_app
import os
from werkzeug.utils import secure_filename
from models.upload import create_upload, update_upload_status
from detectors.file_upload import scan_file

api_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@api_bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Scan file
        status = scan_file(file_path)

        # Save to database
        create_upload(filename, file.filename, file_path, os.path.getsize(file_path), file.mimetype, request.form.get('uploaded_by'))

        if status != 'safe':
            update_upload_status(filename, status)  # Assuming filename as ID for simplicity

        return jsonify({'message': f'File uploaded with status: {status}'}), 200

    return jsonify({'error': 'File type not allowed'}), 400