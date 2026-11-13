"""Verify that the local Hugging Face embedding model works on CPU."""

from sentence_transformers import SentenceTransformer

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def main() -> None:
    model = SentenceTransformer(MODEL_NAME, device="cpu")

    request_summaries = [
        "method=GET route=/products requests_last_minute=5",
        "method=GET route=/users/profile requests_last_minute=3",
        "method=POST route=/orders requests_last_minute=2",
    ]

    embeddings = model.encode(
        request_summaries,
        normalize_embeddings=True,
    )

    print("Model loaded successfully")
    print("Model:", MODEL_NAME)
    print("Number of requests:", len(embeddings))
    print("Embedding shape:", embeddings.shape)
    print("First embedding preview:", embeddings[0][:5])


if __name__ == "__main__":
    main()
