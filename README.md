# Final_Proj_Anoseek

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