from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import pandas as pd
import numpy as np
import pyshark
import joblib
import threading
import nest_asyncio
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ------------------------
# 🎯 Flask & SocketIO Setup
# ------------------------
app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

# Apply nest_asyncio to fix event loop issues
nest_asyncio.apply()

# ------------------------
# 🎉 Load Encoders & Scaler
# ------------------------
try:
    encoder = joblib.load("encoder.pkl")
    scaler = joblib.load("scaler.pkl")
    print("✅ Encoder and Scaler Loaded Successfully!")
except FileNotFoundError:
    encoder = {}
    scaler = StandardScaler()
    print("⚠️ Encoder/Scaler Not Found! Training Required.")

# ------------------------
# 📡 Real-time Monitoring Variables
# ------------------------
monitoring_active = False
monitoring_thread = None
INTERFACE = "\\Device\\NPF_{1875F0DF-387A-4CF9-8679-7FB093D7C5E7}"  # Correct Interface

# ------------------------
# 📚 Feature Names & Categorical Columns
# ------------------------
feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]
categorical_cols = ['protocol_type', 'service', 'flag']

# ------------------------
# 📡 Packet Capture Logic
# ------------------------
def capture_packets():
    """Capture packets and emit data to the frontend."""
    global monitoring_active
    capture = pyshark.LiveCapture(interface=INTERFACE)

    print("✅ Listening for packets...")
    for packet in capture.sniff_continuously(packet_count=0):
        if not monitoring_active:
            break
        try:
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'
            src_ip = packet.ip.src if hasattr(packet, 'ip') else 'Unknown'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'Unknown'
            packet_size = packet.length if hasattr(packet, 'length') else 'Unknown'

            # Create a log entry
            log_entry = f"Protocol: {protocol}, Source: {src_ip}, Destination: {dst_ip}, Size: {packet_size} bytes"
            
            # Emit packet details to frontend
            socketio.emit('new_packet', {'packet': log_entry})

        except Exception as e:
            print(f"⚠️ Error processing packet: {e}")

# ------------------------
# 📡 Start/Stop Monitoring Logic
# ------------------------
def start_monitoring():
    """Start Real-time Monitoring."""
    global monitoring_active, monitoring_thread
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = threading.Thread(target=capture_packets)
        monitoring_thread.start()
        return "✅ Real-time Monitoring Started!"
    else:
        return "⚠️ Monitoring is Already Running."

def stop_monitoring():
    """Stop Real-time Monitoring."""
    global monitoring_active, monitoring_thread
    if monitoring_active:
        monitoring_active = False
        if monitoring_thread:
            monitoring_thread.join()
            monitoring_thread = None
        return "⏹️ Real-time Monitoring Stopped!"
    else:
        return "⚠️ No Active Monitoring to Stop."

# ------------------------
# 🔄 Dynamic Model Training Logic
# ------------------------
def train_model_from_csv():
    """Load, preprocess, and train a model using lda.csv."""
    try:
        # Load lda.csv dynamically
        data_df = pd.read_csv("lda.csv")

        # Encode categorical columns
        for col in categorical_cols:
            if col not in encoder:
                encoder[col] = LabelEncoder()
                data_df[col] = encoder[col].fit_transform(data_df[col].astype(str))
                joblib.dump(encoder, "encoder.pkl")
            else:
                data_df[col] = encoder[col].transform(data_df[col].astype(str))

        # Separate features and target
        X = data_df[feature_names]
        y = data_df['labels']  # Assuming 'label' is the target column

        # Normalize the data
        X_scaled = scaler.fit_transform(X)
        joblib.dump(scaler, "scaler.pkl")

        # Split data for accuracy check
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

        # Train the model dynamically
        dynamic_model = RandomForestClassifier(n_estimators=100, random_state=42)
        dynamic_model.fit(X_train, y_train)

        # Calculate accuracy
        y_pred = dynamic_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"🎯 Model Accuracy: {accuracy * 100:.2f}%")

        return dynamic_model, accuracy

    except Exception as e:
        print(f"⚠️ Error while training model from csv: {e}")
        return None, 0

# ------------------------
# 🎨 Flask Routes
# ------------------------
@app.route("/")
def index():
    """Render Home Page."""
    return render_template("index.html", feature_names=feature_names)

@app.route("/predict", methods=["POST"])
def predict():
    """Handle Prediction Requests with Dynamic Model Training from lda.csv."""
    try:
        # 🔥 Train model dynamically from lda.csv before prediction
        dynamic_model, accuracy = train_model_from_csv()
        if dynamic_model is None:
            return "⚠️ Error: Could not train model from lda.csv!"

        # 🔍 Prepare input for prediction
        data = []
        for feature in feature_names:
            value = request.form.get(feature, "")
            
            # Handle missing or invalid values
            if value == "":
                return f"⚠️ Missing value for feature: {feature}"

            # Handle categorical encoding
            if feature in categorical_cols:
                if value in encoder[feature].classes_:
                    value = encoder[feature].transform([value])[0]
                else:
                    return f"⚠️ Invalid value for {feature}: {value}"

            # Convert numerical values
            try:
                data.append(float(value))
            except ValueError:
                return f"⚠️ Invalid numeric value for {feature}: {value}"

        # 📊 Create input dataframe and scale
        input_df = pd.DataFrame([data], columns=feature_names)
        input_scaled = scaler.transform(input_df)

        # 🚀 Predict with the dynamically trained model
        prediction = dynamic_model.predict(input_scaled)[0]

        # ✅ Generate response based on prediction
        status = "✅ Safe - No Threat Detected" if prediction == "normal" else f"⚠️ Danger! Attack Detected: {prediction}"
        color = "green" if prediction == "normal" else "red"

        return render_template(
            "result.html", 
            label=prediction, 
            status=status, 
            color=color, 
            accuracy=f"{accuracy * 100:.2f}%"
        )

    except Exception as e:
        return f"⚠️ Error: {str(e)}"

@app.route("/monitor")
def monitor():
    """Render Monitor Page."""
    return render_template("monitor.html")

@app.route("/start_monitoring")
def start_monitoring_route():
    """Start Real-time Monitoring Route."""
    result = start_monitoring()
    return result

@app.route("/stop_monitoring")
def stop_monitoring_route():
    """Stop Real-time Monitoring Route."""
    result = stop_monitoring()
    return result

# ------------------------
# 🚀 Run Flask App
# ------------------------
if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
