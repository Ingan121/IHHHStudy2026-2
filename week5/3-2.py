from gliner import GLiNER
ner = GLiNER.from_pretrained("urchade/gliner_multi-v2.1")
ner.predict_entities("고객 김민수 900101-1234567", ["person", "resident_id", "api_key"])