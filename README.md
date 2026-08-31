## Final Project - Anoseek

Submitted by Daniel Cohen & Michal Ben Haim.

## What's Anoseek About?
Anoseek is an E2E project designed to monitor, analyze and investigate network anomalies. 

## Bird's Eye Look at Anoseek
<img width="420" height="313" alt="image" src="https://github.com/user-attachments/assets/fb361bfd-0e8d-4e83-981c-38a5f47db1ab" />

## Anoseek's Components
Anoseek can be broken down into 4 main components:
1. **Classification Agent --> _LSTM-SVC-EMBEDDINGS Model_**

  This model serves as first layer of Anoseek's core. It receives flows of networks extracted to a specific set of 32 features. Upon receiving those, the model predicts if the given flow is anomalous, and if so - classifies it to a certain set of severity ranks (ranging from 1 to 4).

2. **Agent --> _Active Response Algorithm_**

  This layer serves as the enforcement decision apparatus. It receives classification data from the previous layer, calculates statistical estimates, and changes the system's state & active approach accordingly.
  
> [!NOTE]
> Possible system states include IDLE, ALERTED & UNDER-ATTACK. Those directly affect the agent's decision besides the current flow severity. 

3.  **Chatbot --> _RAG_**

  This layer is dedicated to investigation. With Gemini's API, the context is enriched with MITRE ATT&CK (partial) data & event dependent context. Users can ask "general" knowledge data (e.g. types of attack) or event-specific questions (e.g. about a certain IP). 

4.  **Edge Detector --> _Raspberry-Pi_**

Responsible for monitoring the network, extracting flow features and delivering those to the classification layer. It also acts as an active enforcer, via a firewall, for the agent decisions which can be either - block ip or rate limit.

### Code References & Snippets
1. **Classification Model**

- [Model Architecture](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/train_and_evaluate.py#L176)

- [Sequence Windows](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/inference.py#L175)

- [Anomaly Prediction](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/inference.py#L199)

- [API Path --> Classification of CSV recorded flows](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/api.py#L147)[^1]

2. **Agent**

- [Statistical Threshold](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/agent.py#L721)

- [IDLE - System Actions & Transitions](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/agent.py#L727)

- [ALERTED - System Actions & Transitions](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/agent.py#L760)

- [UNDER-ATTACK System Actions & Transitions](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/agent.py#L802)

3. **Chatbot**

- [Multithread Embedding](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/ips_agent_embed.py#L31)

- [Context Building](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/chat.py#L81)

- [Query Enrichment and Handling](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/backend/chat.py#L94)

4. **Edge detector**

- [NFT Creation](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/hardware/sniffer.py#L129)

- [Active Enforcement](https://github.com/DC-055/Final_Proj_Anoseek/blob/de8af948368d7062f5df0844b3bb9cf9d0e77146/hardware/sniffer.py#L168)

### Local Project Activation
1. __activate venv envoirment__

- .\.venv\Scripts\activate

2. __activate backend through vscode terminal__

- cd backend
- py -3.12 -m uvicorn api:app --reload --port 8001
- python -m uvicorn api:app --reload --port 8001  

3. **service discoverable on wi-fi network** (_necessary for active enforcement & scanning with a connected Edge Detector_)
- python -m uvicorn api:app --host 0.0.0.0 --port 8001
4.  **activate frontend**                                
- cd frontend
- npm run dev

* api interface: http://localhost:8001/docs

[^1]: CSV recorded flows (as demonstrated in /datasets) cannot be actively enforced, nonetheless agent decision is presented. 

