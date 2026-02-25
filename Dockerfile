FROM python:3.11-slim 

#Arbeitsverzeichnis
WORKDIR /app

#Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#code kopieren
COPY . .

#Port für Flask
EXPOSE 5000

#Startbefehl
CMD [ "python", "app.py" ]