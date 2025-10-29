# transcribe.py
# Swap this stub with a real ASR later (e.g., Whisper, cloud STT, Vosk).
# Keep the interface stable for your app.

from typing import Optional

def transcribe_file(audio_path: str, lang_hint: Optional[str] = None) -> str:
    """
    Return a UTF-8 transcript for the given audio file.
    For now this is a stub that just marks where ASR output would go.

    Parameters:
        audio_path: local filesystem path to audio
        lang_hint:  ISO language code like 'de', 'en', 'fr', or 'auto'

    Replace with your preferred engine later. Keep this signature.
    """
    # TODO: plug real ASR here (WhisperX/Vosk/Cloud). Handle diarization later.
    return f"[transcript placeholder for {audio_path} | lang={lang_hint or 'auto'}]"
