import os
import argparse
from azure.identity import ClientSecretCredential
from openai import AzureOpenAI
from typing import List, Dict, Optional, Protocol


# Azure AD credentials
tenant_id = ""
client_id = ""
client_secret = ""


# ============================================
# Azure OpenAI resource details
# ============================================
azure_openai_endpoint = "https://aiservicesprjnttsdcdevbwmot001.services.ai.azure.com/"
deployment_name = "gpt-4o"  # or your custom deployment name
api_version = "2024-12-01-preview"

# Authenticate using Service Principal
credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=client_secret
)

token = credential.get_token("https://cognitiveservices.azure.com/.default")

client = AzureOpenAI(
    api_key=token.token,
    api_version=api_version,
    azure_endpoint=azure_openai_endpoint,
    azure_deployment=deployment_name,
    azure_ad_token_provider=lambda: token.token
)

messages = [{"role": "system", "content": "You are a helpful assistant."}]
last_reply = ""
log_file = "../swipl-devel/build/myfile3.pl"
log_file2 = "../swipl-devel/build/myfile4.pl"


# ============================================
# Input handling classes
# ============================================

class InputReader(Protocol):
    def read(self) -> Optional[str]:
        ...


class DoubleQuotedInputReader:
    PROMPT = 'You (start with "): '

    def read(self) -> Optional[str]:
        first_line = input(self.PROMPT).strip()

        if first_line.lower() in {"exit", "quit", "done", "commit", "commit2"}:
            return first_line.lower()

        if not first_line.startswith('"'):
            print('⚠ Input must begin with a double quote ("). Try again.')
            return None

        # Single-line quoted input
        if first_line.count('"') >= 2:
            return first_line.split('"', 1)[1].rsplit('"', 1)[0].strip()

        content_lines: List[str] = [first_line[1:]]
        print('Enter your message inside double quotes ("). Input ends after the second quote is entered.')
        quote_count = 1

        while True:
            line = input()
            quote_count += line.count('"')

            if quote_count >= 2:
                before_close = line.split('"', 1)[0]
                content_lines.append(before_close)
                break
            else:
                content_lines.append(line)

        return "\n".join(content_lines).strip()


# ============================================
# Chat logging
# ============================================

class ChatLogger:
    def __init__(self, path: str, path2: str):
        self._path = path
        self._path2 = path2

    def save(self, text: str) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"✅ Last ChatGPT reply saved to '{self._path}'.")

    def save2(self, text: str) -> None:
        with open(self._path2, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"✅ Last ChatGPT reply saved to '{self._path2}'.")


# ============================================
# Azure OpenAI Chat wrapper
# ============================================

class ChatService(Protocol):
    def send(self, messages: List[Dict[str, str]]) -> str:
        ...


class AzureOpenAIChatService:
    def __init__(self, sdk_client: AzureOpenAI, model: str = "gpt-4o", temperature: float = 0.7):
        self._client = sdk_client
        self._model = model
        self._temperature = temperature

    def send(self, messages: List[Dict[str, str]]) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=self._temperature
        )
        if not response or not response.choices or not response.choices[0].message:
            raise RuntimeError("Empty response from Azure OpenAI.")
        return response.choices[0].message.content.strip()


# ============================================
# Main Chat Application
# ============================================

class ChatApp:
    def __init__(
        self,
        chat_service: ChatService,
        input_reader: InputReader,
        logger: ChatLogger,
        initial_messages: Optional[List[Dict[str, str]]] = None,
    ):
        self.messages: List[Dict[str, str]] = initial_messages[:] if initial_messages else []
        self.chat_service = chat_service
        self.input_reader = input_reader
        self.logger = logger
        self._last_reply: str = ""

    def print_intro(self) -> None:
        print("Start chatting with ChatGPT.")
        print('- Enter input wrapped in double quotes, e.g.:\n  "Paragraph 1...\n   Paragraph 2..."\n')
        print('- Type `commit` to save the last ChatGPT reply.')
        print('- Type `commit2` to save to secondary file.')
        print('- Type `exit` to quit without saving.\n')

    def handle_command(self, cmd: str) -> bool:
        if cmd in {"exit", "quit", "done"}:
            print("Exiting. No response saved.")
            return True

        if cmd == "commit":
            if self._last_reply:
                self.logger.save(self._last_reply)
            else:
                print("⚠ No reply to commit.")
            return False

        if cmd == "commit2":
            if self._last_reply:
                self.logger.save2(self._last_reply)
            else:
                print("⚠ No reply to commit.")
            return False

        print(f"Unrecognized command: {cmd}")
        return False

    def send_message(self, user_input: str):
        self.messages.append({"role": "user", "content": user_input})
        reply = self.chat_service.send(self.messages)
        print(f"\nChatGPT: {reply}\n")
        self.messages.append({"role": "assistant", "content": reply})
        self._last_reply = reply

    def run(self, file_input: Optional[str] = None) -> None:
        self.print_intro()

        # If a file input is provided, send it first
        if file_input:
            print(f"📄 Sending contents of file as initial input...\n")
            self.send_message(file_input)

        # Then continue interactive conversation
        while True:
            user_input = self.input_reader.read()

            if user_input is None:
                continue

            if user_input in {"exit", "quit", "done", "commit", "commit2"}:
                should_end = self.handle_command(user_input)
                if should_end:
                    break
                else:
                    continue

            try:
                self.send_message(user_input)
            except Exception as e:
                print(f"❌ Error: {e}")
                break


# ============================================
# File helper
# ============================================

def read_file_content(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return None


# ============================================
# Entry point
# ============================================

def main() -> None:
    parser = argparse.ArgumentParser(description="ChatGPT with Azure OpenAI and optional file input.")
    parser.add_argument("--file", type=str, help="Path to input text file.")
    args = parser.parse_args()

    chat_service = AzureOpenAIChatService(sdk_client=client, model="gpt-4o", temperature=0.7)
    input_reader = DoubleQuotedInputReader()
    logger = ChatLogger(log_file, log_file2)
    app = ChatApp(chat_service=chat_service, input_reader=input_reader, logger=logger, initial_messages=messages)

    file_content = read_file_content(args.file) if args.file else None
    app.run(file_input=file_content)


if __name__ == "__main__":
    main()

