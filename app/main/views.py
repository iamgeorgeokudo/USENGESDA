from flask import render_template, redirect, request, url_for, flash
from flask_login import login_required
from . import main
import pandas as pd
import nltk
import sklearn
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

nltk.download('punkt')
nltk.download('stopwords')


data = pd.read_csv('sdaproject.csv')

stop_words = set(stopwords.words('english'))
data['cleaned_text'] = data['question'].apply(
    lambda x: ' '.join([word for word in x.split() if word.lower() not in stop_words]))

tfidf = TfidfVectorizer()
tfidf_matrix = tfidf.fit_transform(data['cleaned_text'])

def get_response(user_input):
    user_input = ' '.join([word for word in user_input.split() if word.lower() not in stop_words])
    user_input_tfidf = tfidf.transform([user_input])
    similarities = cosine_similarity(user_input_tfidf, tfidf_matrix)
    most_similar_index = similarities.argmax()
    similarity_score = similarities.max()

    # Set a threshold for the similarity score
    threshold = 0.3

    if similarity_score < threshold:
        return "Sorry, I can't answer that."
    else:
        return data.iloc[most_similar_index]['answer']

@main.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('main/index.html')

@main.route('/about')
@login_required
def about():
    return render_template('main/about.html')

@main.route('/get_response', methods=['POST'])
def get_response_route():
    user_input = request.form['user_input']
    response = get_response(user_input)
    return response

@main.route('/chat')
@login_required
def chat():
    return render_template('response.html')

@main.route('/contact')
@login_required
def contact():
    return render_template('main/contact.html')

@main.route('/events')
@login_required
def events():
    return render_template('main/events.html')