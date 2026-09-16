import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class StylometryAnalyzer:
    def __init__(self):
        # Character n-grams (3-5 letters) capture stylistic quirks, typos, and syntax habits
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))

    @staticmethod
    def extract_lexical_features(text: str) -> dict:
        """Extracts structural and punctuation metrics from text."""
        sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
        words = re.findall(r'\b\w+\b', text)
        
        avg_sentence_len = len(words) / max(len(sentences), 1)
        avg_word_len = sum(len(w) for w in words) / max(len(words), 1)
        punctuation_count = len(re.findall(r'[,;:!?"\'\(\)\-\.]', text))
        uppercase_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)

        return {
            "avg_sentence_length": round(avg_sentence_len, 2),
            "avg_word_length": round(avg_word_len, 2),
            "punctuation_density": round(punctuation_count / max(len(words), 1), 3),
            "uppercase_ratio": round(uppercase_ratio, 3)
        }

    def compute_similarity(self, text_sample_a: str, text_sample_b: str) -> dict:
        """Compares two text corpora and outputs an AI similarity percentage."""
        # 1. Compute Character TF-IDF Vector Similarity
        tfidf_matrix = self.vectorizer.fit_transform([text_sample_a, text_sample_b])
        cos_sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]

        # 2. Extract Lexical Footprints
        stats_a = self.extract_lexical_features(text_sample_a)
        stats_b = self.extract_lexical_features(text_sample_b)

        # 3. Formulate Match Score
        similarity_score = round(float(cos_sim), 4)

        return {
            "stylometric_similarity_score": similarity_score,
            "match_confidence": "HIGH" if similarity_score >= 0.75 else "MEDIUM" if similarity_score >= 0.50 else "LOW",
            "sample_a_metrics": stats_a,
            "sample_b_metrics": stats_b
        }

if __name__ == "__main__":
    analyzer = StylometryAnalyzer()

    # Post from Dread Forum (Target: DreadOps)
    SAMPLE_A = '''
    Hey guys... fresh dump available today! We got full db access, clean sql dumps, no duplicates. 
    Payment strictly via Monero; don't waste my time with btc or bargaining. Ping me on xmpp.
    '''

    # Post from Exploit Market (Target: ApexBreach)
    SAMPLE_B = '''
    Fresh leaked db dropped today... completely untouched sql records, no duplicate rows. 
    Strictly XMR transactions only! Do not waste my time bargaining. Drop a note on jabber for rates.
    '''

    # Unrelated control sample
    CONTROL_SAMPLE = '''
    Hello everyone. Could someone explain how to configure a Tor circuit relay on Debian 12?
    I followed the official documentation, but the service fails to bind on port 9050.
    '''

    print("[*] Running AI Stylometric Analysis between DreadOps and ApexBreach...")
    match_result = analyzer.compute_similarity(SAMPLE_A, SAMPLE_B)
    print(f"    -> Stylometric Cosine Similarity: {match_result['stylometric_similarity_score'] * 100:.2f}%")
    print(f"    -> Linguistic Match Rating: {match_result['match_confidence']}")

    print("\n[*] Comparing against unrelated control post...")
    control_result = analyzer.compute_similarity(SAMPLE_A, CONTROL_SAMPLE)
    print(f"    -> Stylometric Cosine Similarity: {control_result['stylometric_similarity_score'] * 100:.2f}%")
    print(f"    -> Linguistic Match Rating: {control_result['match_confidence']}")
