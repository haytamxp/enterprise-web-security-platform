import os
import glob
from dotenv import load_dotenv
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_qdrant import QdrantVectorStore
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = os.getenv("QDRANT_PORT", "6333")
QDRANT_URL = f"http://{QDRANT_HOST}:{QDRANT_PORT}"

def get_rag_chain():
    """Construit la chaîne RAG complète (Indexation + LLM)"""
    
    # 1. Chargement des documents
    docs = []
    for filepath in glob.glob("playbooks/*.txt"):
        loader = TextLoader(filepath, encoding='utf-8')
        docs.extend(loader.load())

    if not docs:
        raise ValueError("Aucun document trouvé dans le dossier playbooks/")

    # 2. Chunking
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    chunks = text_splitter.split_documents(docs)

    # 3. Embeddings & Vector Store (Qdrant)
    embeddings = GoogleGenerativeAIEmbeddings(
        model="models/embedding-001", 
        google_api_key=GEMINI_API_KEY
    )
    
    # On utilise force_recreate=True pour le dev (recrée la collection à chaque fois)
    # En production, on utiliserait plutôt un système de mise à jour
    vectorstore = QdrantVectorStore.from_documents(
        documents=chunks,
        embedding=embeddings,
        url=QDRANT_URL,
        collection_name="orchid_playbooks",
        force_recreate=True 
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": 2})

    # 4. LLM (Gemini)
    llm = ChatGoogleGenerativeAI(
        model="gemini-3.7-flash",
        google_api_key=GEMINI_API_KEY,
        temperature=0
    )

    # 5. Prompt
    prompt = ChatPromptTemplate.from_template("""
    Tu es un expert en cybersécurité. Réponds à la question en te basant UNIQUEMENT sur le contexte fourni.
    Si la réponse n'est pas dans le contexte, dis "Je ne trouve pas cette information."
    
    Contexte : {context}
    Question : {question}
    Réponse :
    """)

    # 6. Chaîne
    chain = (
        {"context": retriever, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )
    
    return chain

def enrich_incident_with_rag(incident):
    """
    Prend un incident, utilise le RAG pour générer une recommandation.
    """
    query = f"Comment réagir face à un incident de type {incident['title']} ?"
    
    try:
        chain = get_rag_chain()
        response = chain.invoke(query)
        incident['ai_recommendation'] = response
    except Exception as e:
        print(f"⚠️ Erreur RAG: {e}")
        incident['ai_recommendation'] = "Erreur lors de la génération de la recommandation."
        
    return incident