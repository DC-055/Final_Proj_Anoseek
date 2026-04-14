<<<<<<< HEAD
<<<<<<< HEAD
# Final_Proj_Anoseek
<<<<<<< HEAD

# activate venv envoirment
.venv\Scripts\activate

# activate backend through pycharm terminal
cd backend
py -3.12 -m uvicorn api:app --reload --port 8001

# show api interface:
http://localhost:8001/docs

# activate frontend
cd frontend
npm run dev
=======
>> 1. AUTOENCODER_LSTM
>> 2. ARCS
>> 3. CHATBOT -> LLM API
>>>>>>> c15f403 (test commit)
=======
# Final_Proj_Anoseek
>>>>>>> 9aad3b4 (Bring in Daniel's latest branch contents after force-push)
=======
# Final_Proj_Anoseek
Activation steps:
- BACKEND:
1. From /backend: (JUST ONCE!) python train_and_save.py --data ../datasets/NF-UNSW-NB15-v2_50000.csv
2. API: uvicorn backend.api:app --host 127.0.0.1 --port 8001 --access-log
   (If needed - pip install uvicorn / pip install python-multipart)
- FRONTEND:
1. Fron /frontend: npm install
2. npm run dev
>>>>>>> aa24be6 (updated readme.md file with instructions + minor fixes to train_and_save.py)
