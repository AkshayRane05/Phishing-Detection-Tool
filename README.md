# Email Phishing Detection

![GitHub](https://img.shields.io/github/license/AkshayRane05/phishing-detection-tool)
![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange.svg)

A real-time email phishing detection system that monitors your inbox for suspicious emails and automatically moves potential phishing attempts to the spam folder. Built with machine learning, this system analyzes both email content and embedded URLs to identify threats.

## 🚀 Features

- **Real-time Email Monitoring**: Continuously checks your inbox for new messages
- **Machine Learning Classification**: Uses a trained TensorFlow model to analyze email content
- **URL Threat Detection**: Verifies links against Google Safe Browsing API
- **Automatic Spam Management**: Moves detected phishing emails to spam folder
- **Parallel Processing**: Efficiently processes multiple emails simultaneously

## 📋 Requirements

- Python 3.7+
- Raspberry Pi (for deployment)
- Gmail account
- Google API key (for Safe Browsing API)
- Internet connection

## 🔧 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/AkshayRane05/email-phishing-detection.git
   cd email-phishing-detection
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Download NLTK data:
   ```bash
   python -c "import nltk; nltk.download('stopwords')"
   ```

4. Configure your Gmail account:
   - Enable IMAP in your Gmail settings
   - Generate an App Password if you have 2FA enabled

5. Update the credentials in the code:
   ```python
   EMAIL_ACCOUNT = "your-email@gmail.com"
   EMAIL_PASSWORD = "your-app-password"
   ```

6. Get a Google Safe Browsing API key:
   - Visit the [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project and enable the Safe Browsing API
   - Generate an API key and update it in the code:
   ```python
   API_KEY = "your-google-api-key"
   ```

## 💻 Usage

1. Ensure you have the trained model files:
   - `phishing_email_detection_model.h5`
   - `tokenizer.pkl`

   (If you don't have these files, check the [Model Training](#-model-training) section below)

2. Run the email listener:
   ```bash
   python email_phishing_detector.py
   ```

3. The system will:
   - Connect to your Gmail inbox
   - Continuously check for new emails
   - Analyze each new email for phishing attempts
   - Move suspected phishing emails to the spam folder
   - Print detailed analysis in the console

4. To stop the program, press `Ctrl+C`

## 📊 Results

![Detection Example](images/detection_example.png)
*Example of the system detecting a phishing email with confidence score and analysis results.*

![System Architecture](images/system_architecture.png)
*Architecture diagram showing the email processing pipeline.*

![Performance Metrics](images/model_performance.png)
*Model evaluation metrics showing accuracy, precision, and recall on test data.*

## 🧠 Model Training

This repository includes a pre-trained model, but if you want to train your own:

1. Collect a dataset of phishing and legitimate emails
2. Preprocess the data using the `clean_text()` function
3. Train a model using TensorFlow (sample script provided in `train_model.py`)
4. Save the model as `phishing_email_detection_model.h5`
5. Save the tokenizer as `tokenizer.pkl`

## 🔄 How It Works

1. **Email Fetching**: Connects to Gmail via IMAP and retrieves new emails
2. **Content Analysis**: 
   - Cleans and preprocesses email text
   - Passes the text through a trained neural network
   - Determines phishing probability score
3. **URL Checking**:
   - Extracts URLs from email content
   - Verifies each URL against Google Safe Browsing API
4. **Action Taking**:
   - Moves emails identified as phishing to spam folder
   - Marks processed emails as read

## 🔒 Security Notes

- Store your email password and API keys securely
- Consider using environment variables instead of hardcoding credentials
- Regularly update the model to adapt to new phishing techniques
- This tool is meant for personal use - respect privacy laws when deploying in multi-user environments

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [NLTK](https://www.nltk.org/) for natural language processing
- [TensorFlow](https://www.tensorflow.org/) for machine learning capabilities
- [Google Safe Browsing API](https://developers.google.com/safe-browsing) for URL verification
