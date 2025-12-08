# This file is part of Rise ToolKit.
# Copyright (c) 2025  Routo

# Rise ToolKit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# You should have received a copy of the GNU General Public License
# along with Rise ToolKit. If not, see <https://www.gnu.org/licenses/>.



import sys
import websocket
import json
import threading
import time
import ssl
import requests
import struct
import socket
import base64
import os
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

TOKENS_FILE = "tokens.txt"
DATA_FILE = "rise_toolkit_data.json"


def resource_path(relative_path: str) -> str:
    """ Get absolute path to resource, works for PyInstaller """
    if getattr(sys, "frozen", False):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)

@dataclass
class StatusConfig:
    text: str = ""
    emoji_name: Optional[str] = None
    emoji_id: Optional[str] = None

@dataclass
class ToolkitSettings:
    server_id: str = ""
    channel_id: str = ""
    status_configs: List[StatusConfig] = field(default_factory=list)
    status_rotation_delay: int = 10
    bio_text: str = ""

@dataclass
class TokenInfo:
    token: str
    user_id: str = ""
    username: str = ""
    guilds: List[str] = field(default_factory=list)
    voice_channel: Optional[str] = None
    voice_guild: Optional[str] = None
    ws: Any = None
    voice_ws: Any = None
    udp_socket: Any = None
    voice_connected: bool = False
    udp_connected: bool = False
    secret_key: bytes = b""
    ssrc: int = 0
    sequence: int = 0
    timestamp: int = 0
    session_id: Optional[str] = None
    endpoint: Optional[str] = None
    voice_token: Optional[str] = None
    mute: bool = False
    deaf: bool = False
    status: str = "online"
    activity: Optional[Dict] = None
    last_heartbeat: float = 0.0
    connected: bool = False
    latency: float = 0.0
    heartbeat_interval: float = 0.0
    heartbeat_thread: Any = None
    voice_heartbeat_thread: Any = None
    ws_running: bool = False
    voice_ws_running: bool = False
    keepalive_thread: Any = None
    keepalive_running: bool = False
    bio_text: str = ""
    status_configs: List[StatusConfig] = field(default_factory=list)
    current_status_index: int = 0
    status_rotation_enabled: bool = False
    status_rotation_delay: int = 10
    status_rotation_thread: Any = None
    status_rotation_running: bool = False
    heartbeat_running: bool = False
    session_established: bool = False




# ++++++++++++++++++++++ Main Engine Class +++++++++++++++++++++++++

class RiseEngine(QObject):
    signal_log = pyqtSignal(str, str)
    signal_token_update = pyqtSignal(str, dict)
    
    def __init__(self):
        super().__init__()
        self.tokens: Dict[str, TokenInfo] = {}
        self.settings = ToolkitSettings()
        self.ws_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json"
        }
        self.WATERMARK_STATUS = StatusConfig(text="Vc -- Rise Toolkit By Routo", emoji_name="⚡")
        self.initialize_application()
    
    def initialize_application(self):
        """Initialize application with proper settings loading order"""
        try:
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                self.settings.server_id = data.get("server_id", "")
                self.settings.channel_id = data.get("channel_id", "")
                
                # Load status configurations from file
                status_configs = data.get("status_configs", [])
                self.settings.status_configs = [
                    StatusConfig(
                        text=c.get("text", ""),
                        emoji_name=c.get("emoji_name"),
                        emoji_id=c.get("emoji_id")
                    ) for c in status_configs[:2]
                ]
                
                self.settings.status_rotation_delay = data.get("status_rotation_delay", 10)
                self.settings.bio_text = data.get("bio_text", "")
            
            self.load_tokens_from_file()
            self.signal_log.emit("SUCCESS", "Application initialized successfully")
            
        except Exception as e:
            self.signal_log.emit("ERROR", f"Initialization failed: {e}")
    
    def load_tokens_from_file(self):
        """Load tokens from tokens.txt file"""
        try:
            if not os.path.exists(TOKENS_FILE):
                self.signal_log.emit("INFO", f"{TOKENS_FILE} not found")
                return
            
            loaded_count = 0
            with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    token = line.strip()
                    if not token or '.' not in token:
                        continue
                    
                    token = token.strip('"\' ')
                    token_id = self.extract_token_id(token)
                    
                    if not self.is_token_valid(token):
                        continue
                    
                    headers = {"Authorization": token, **self.ws_headers}
                    user_data = self.api_request("GET", "https://discord.com/api/v9/users/@me", headers)
                    
                    if not user_data:
                        self.signal_log.emit("WARNING", f"Line {line_num}: Token validation failed")
                        continue
                    
                    if token in [t.token for t in self.tokens.values()]:
                        continue
                    
                    token_info = TokenInfo(
                        token=token,
                        user_id=user_data['id'],
                        username=f"{user_data['username']}#{user_data.get('discriminator', '0')}"
                    )
                    
                    self.tokens[token_id] = token_info
                    loaded_count += 1
                    self.signal_log.emit("DEBUG", f"Loaded token: {token_info.username}")
            
            if loaded_count:
                self.signal_log.emit("SUCCESS", f"Loaded {loaded_count} tokens")
            else:
                self.signal_log.emit("INFO", "No valid tokens found")
                
        except Exception as e:
            self.signal_log.emit("ERROR", f"Token loading failed: {e}")
    
    def extract_token_id(self, token: str) -> str:
        """Extract token ID from token string"""
        try:
            parts = token.split('.')
            if len(parts) >= 3:
                return parts[0]
            return hashlib.md5(token.encode()).hexdigest()[:8]
        except:
            return hashlib.md5(token.encode()).hexdigest()[:8]
    
    def is_token_valid(self, token: str) -> bool:
        """Check if token format is valid"""
        return '.' in token and len(token.split('.')) >= 3
    
    def api_request(self, method: str, url: str, headers: Dict, json_data: Optional[Dict] = None, timeout: int = 10):
        """Make API request with error handling"""
        try:
            response = requests.request(method, url, headers=headers, json=json_data, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None
    
    def save_application_settings(self):
        """Save all application settings to files"""
        try:
            self.save_tokens_to_file()
            
            # Prepare settings data
            data = {
                "server_id": self.settings.server_id,
                "channel_id": self.settings.channel_id,
                "status_configs": [
                    {"text": c.text, "emoji_name": c.emoji_name, "emoji_id": c.emoji_id}
                    for c in self.settings.status_configs[:2]
                ],
                "status_rotation_delay": self.settings.status_rotation_delay,
                "bio_text": self.settings.bio_text
            }
            
            with open(DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.signal_log.emit("SUCCESS", "Settings saved (2 user statuses + 1 watermark)")
            return True
        except Exception as e:
            self.signal_log.emit("ERROR", f"Settings save failed: {e}")
            return False
    
    def save_tokens_to_file(self):
        """Save tokens to tokens.txt file"""
        try:
            with open(TOKENS_FILE, 'w', encoding='utf-8') as f:
                for token_data in self.tokens.values():
                    f.write(f"{token_data.token}\n")
            return True
        except Exception as e:
            self.signal_log.emit("ERROR", f"Token save failed: {e}")
            return False
    
    def add_new_token(self, token: str) -> Tuple[bool, str]:
        """Add new token with validation"""
        token = token.strip()
        if not self.is_token_valid(token):
            return False, "Invalid token format"
        
        if token in [t.token for t in self.tokens.values()]:
            return False, "Token already exists"
        
        token_id = self.extract_token_id(token)
        if token_id in self.tokens:
            return False, "Token ID already exists"
        
        headers = {"Authorization": token, **self.ws_headers}
        user_data = self.api_request("GET", "https://discord.com/api/v9/users/@me", headers)
        
        if not user_data:
            return False, "Token validation failed"
        
        token_info = TokenInfo(
            token=token,
            user_id=user_data['id'],
            username=f"{user_data['username']}#{user_data.get('discriminator', '0')}",
        )
        
        self.tokens[token_id] = token_info
        self.save_tokens_to_file()
        
        self.signal_log.emit("SUCCESS", f"Added: {token_info.username}")
        self.signal_token_update.emit(token_id, {
            "username": token_info.username,
            "connected": False,
            "voice_connected": False,
        })
        
        return True, f"Added: {token_info.username}"
    
    def establish_connections(self):
        """Establish WebSocket connections for all tokens"""
        if not self.tokens:
            self.signal_log.emit("INFO", "No tokens to connect")
            return
        
        self.signal_log.emit("INFO", f"Connecting {len(self.tokens)} tokens...")
        success_count = 0
        
        for token_id, token_data in list(self.tokens.items()):
            if self._initiate_connection(token_data):
                success_count += 1
            time.sleep(0.5)
        
        if success_count:
            self.signal_log.emit("SUCCESS", f"Connections established: {success_count}/{len(self.tokens)}")
    
    def _initiate_connection(self, token_data: TokenInfo) -> bool:
        """Initiate WebSocket connection for single token"""
        try:
            headers = {"Authorization": token_data.token, **self.ws_headers}
            response = requests.get("https://discord.com/api/v9/gateway", headers=headers, timeout=15)
            
            if response.status_code != 200:
                return False
            
            gateway = response.json()
            ws_url = f"{gateway['url']}?v=9&encoding=json"

            try:
                if hasattr(websocket, "enableTrace"):
                    websocket.enableTrace(False)
            except Exception:
                pass
            token_data.ws = websocket.WebSocketApp(
                ws_url,
                on_message=lambda ws, msg: self._handle_ws_message(ws, msg, token_data),
                on_error=lambda ws, err: self._handle_ws_error(ws, err, token_data),
                on_close=lambda ws, code, msg: self._handle_ws_close(ws, code, msg, token_data),
                on_open=lambda ws: self._handle_ws_open(ws, token_data),
                header=headers
            )
            
            token_data.ws_running = True
            token_data.session_established = False
            
            thread = threading.Thread(
                target=self._websocket_thread, 
                args=(token_data,), 
                daemon=True,
                name=f"WS-{token_data.user_id[:8]}"
            )
            thread.start()
            
            return True
            
        except Exception as e:
            self.signal_log.emit("ERROR", f"Connection failed: {token_data.username}: {e}")
            return False
    
    def _websocket_thread(self, token_data: TokenInfo):
        """WebSocket thread handler"""
        try:
            token_data.ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, ping_interval=30, ping_timeout=10)
        except Exception as e:
            self.signal_log.emit("ERROR", f"WebSocket error: {token_data.username}: {e}")
        finally:
            token_data.ws_running = False
    
    def _handle_ws_open(self, ws, token_data: TokenInfo):
        self.signal_log.emit("SUCCESS", f"Connected: {token_data.username}")
    
    def _send_identify(self, token_data: TokenInfo):
        identify = {
            'op': 2,
            'd': {
                'token': token_data.token,
                'properties': {'$os': 'windows', '$browser': 'chrome', '$device': 'pc'},
                'compress': False,
                'large_threshold': 250,
                'v': 9
            }
        }
        self._send_websocket_data(token_data, identify)
    
    def _send_websocket_data(self, token_data: TokenInfo, data: Dict) -> bool:
        """Send data through WebSocket"""
        if not token_data.ws_running or not token_data.ws:
            return False
        
        try:
            token_data.ws.send(json.dumps(data))
            return True
        except Exception as e:
            self.signal_log.emit("ERROR", f"Send failed: {token_data.username}: {e}")
            return False
    
    def _handle_ws_message(self, ws, message, token_data: TokenInfo):
        try:
            data = json.loads(message)
            token_data.sequence = data.get('s', token_data.sequence)
            
            if data['op'] == 10:
                token_data.heartbeat_interval = data['d']['heartbeat_interval'] / 1000.0
                
                if token_data.ws_running and not token_data.session_established:
                    self._initiate_heartbeat(token_data)
                    self._send_identify(token_data)
            
            elif data['op'] == 0:
                self._process_dispatch(token_data, data['t'], data['d'])
            
            elif data['op'] == 1:
                self._send_websocket_data(token_data, {"op": 1, "d": token_data.sequence})
            
            elif data['op'] == 11:
                token_data.latency = time.time() - token_data.last_heartbeat
            
            elif data['op'] == 9:
                self.signal_log.emit("WARNING", f"Invalid session: {token_data.username}")
                token_data.session_established = False
                if data['d']:
                    time.sleep(2)
                    self._send_identify(token_data)
                    
        except Exception as e:
            self.signal_log.emit("ERROR", f"Message error: {token_data.username}: {e}")
    
    def _initiate_heartbeat(self, token_data: TokenInfo):
        """Start heartbeat thread"""
        if token_data.heartbeat_thread and token_data.heartbeat_thread.is_alive():
            token_data.heartbeat_running = False
            token_data.heartbeat_thread.join(timeout=1)
        
        token_data.heartbeat_running = True
        token_data.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, 
            args=(token_data,), 
            daemon=True,
            name=f"Heartbeat-{token_data.user_id[:8]}"
        )
        token_data.heartbeat_thread.start()
    
    def _heartbeat_loop(self, token_data: TokenInfo):
        while token_data.ws_running and token_data.heartbeat_running:
            try:
                heartbeat = {'op': 1, 'd': token_data.sequence}
                if self._send_websocket_data(token_data, heartbeat):
                    token_data.last_heartbeat = time.time()
                time.sleep(token_data.heartbeat_interval)
            except Exception:
                break
    
    def _process_dispatch(self, token_data: TokenInfo, event: str, data: Dict):
        token_id = self.extract_token_id(token_data.token)
        
        if event == "READY":
            token_data.user_id = data['user']['id']
            token_data.username = f"{data['user']['username']}#{data['user'].get('discriminator', '0')}"
            token_data.session_id = data['session_id']
            token_data.session_established = True
            
            if 'guilds' in data:
                token_data.guilds = [guild['id'] for guild in data['guilds']]
            
            token_data.connected = True
            self.signal_log.emit("SUCCESS", f"Ready: {token_data.username}")
            
            self.signal_token_update.emit(token_id, {
                "username": token_data.username,
                "guilds": len(token_data.guilds),
                "connected": True,
                "status": "online"
            })
            
            if token_data.bio_text:
                self.set_user_bio(token_data, token_data.bio_text)
            
            if self.settings.status_configs:
                token_data.status_configs = self.settings.status_configs[:2]
                token_data.status_rotation_delay = self.settings.status_rotation_delay
                
                if hasattr(token_data, 'status_rotation_enabled') and token_data.status_rotation_enabled:
                    self.start_status_rotation(token_data, 
                                             token_data.status_configs, 
                                             token_data.status_rotation_delay, 
                                             True)
        
        elif event == "VOICE_STATE_UPDATE":
            if data['user_id'] == token_data.user_id:
                token_data.voice_channel = data.get('channel_id')
                token_data.voice_guild = data.get('guild_id')
                token_data.voice_connected = token_data.voice_channel is not None
                
                self.signal_token_update.emit(token_id, {
                    "voice_connected": token_data.voice_connected,
                    "voice_channel": token_data.voice_channel
                })
    
    def _handle_ws_error(self, ws, error, token_data: TokenInfo):
        self.signal_log.emit("ERROR", f"WebSocket error: {token_data.username}: {error}")
    
    def _handle_ws_close(self, ws, close_status_code, close_msg, token_data: TokenInfo):
        token_data.ws_running = False
        token_data.connected = False
        token_data.session_established = False
        
        if hasattr(token_data, 'heartbeat_running'):
            token_data.heartbeat_running = False
        
        token_id = self.extract_token_id(token_data.token)
        self.signal_token_update.emit(token_id, {"connected": False})
        
        if close_status_code == 4005:
            time.sleep(5)
            if token_id in self.tokens:
                self._initiate_connection(self.tokens[token_id])
    
    def join_voice_channel(self, token_data: TokenInfo, guild_id: str, channel_id: str) -> bool:
        if not token_data.connected:
            return False
        
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': guild_id,
                'channel_id': channel_id,
                'self_mute': token_data.mute,
                'self_deaf': token_data.deaf,
                'self_video': False
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def leave_voice_channel(self, token_data: TokenInfo) -> bool:
        if not token_data.voice_guild:
            return False
        
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': token_data.voice_guild,
                'channel_id': None,
                'self_mute': False,
                'self_deaf': False
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def toggle_mute_state(self, token_data: TokenInfo) -> bool:
        if not token_data.voice_guild:
            return False
        
        token_data.mute = not token_data.mute
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': token_data.voice_guild,
                'channel_id': token_data.voice_channel,
                'self_mute': token_data.mute,
                'self_deaf': token_data.deaf
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def toggle_deafen_state(self, token_data: TokenInfo) -> bool:
        if not token_data.voice_guild:
            return False
        
        token_data.deaf = not token_data.deaf
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': token_data.voice_guild,
                'channel_id': token_data.voice_channel,
                'self_mute': token_data.mute,
                'self_deaf': token_data.deaf
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def set_user_status(self, token_data: TokenInfo, status: str) -> bool:
        if not token_data.connected:
            return False
        
        payload = {
            "op": 3,
            "d": {
                "since": 0,
                "activities": [],
                "status": status,
                "afk": False
            }
        }
        
        if self._send_websocket_data(token_data, payload):
            token_data.status = status
            return True
        return False
    
    def set_user_bio(self, token_data: TokenInfo, bio: str) -> bool:
        try:
            clean_bio = bio.replace('\n', ' ').strip()[:190]
            
            headers = {"Authorization": token_data.token, **self.ws_headers}
            endpoints = ["https://discord.com/api/v9/users/@me/profile", "https://discord.com/api/v9/users/@me"]
            
            for endpoint in endpoints:
                response = requests.patch(endpoint, headers=headers, json={"bio": clean_bio}, timeout=10)
                if response.status_code in [200, 201, 204]:
                    token_data.bio_text = clean_bio
                    self.settings.bio_text = clean_bio
                    self.save_application_settings()
                    return True
            
            return False
        except Exception as e:
            self.signal_log.emit("ERROR", f"Bio error: {token_data.username}: {e}")
            return False
    
    def set_custom_user_status(self, token_data: TokenInfo, text: str, emoji_name: str = None, emoji_id: str = None) -> bool:
        if not token_data.connected:
            return False
        
        emoji = None
        if emoji_name:
            emoji = {"name": emoji_name}
            if emoji_id:
                emoji["id"] = emoji_id
        
        activity = {
            "name": "Custom Status",
            "type": 4,
            "state": text,
        }
        
        if emoji:
            activity["emoji"] = emoji
        
        payload = {
            "op": 3,
            "d": {
                "since": 0,
                "activities": [activity] if text or emoji else [],
                "status": token_data.status,
                "afk": False
            }
        }
        
        return self._send_websocket_data(token_data, payload)
    
    def start_status_rotation(self, token_data: TokenInfo, configs: List[StatusConfig], delay: int = 10, enabled: bool = True):
        """Start status rotation for a token (2 user + 1 watermark = 3 total)"""
        if not configs:
            self.signal_log.emit("WARNING", "No status configurations provided")
            return
        
        token_data.status_configs = configs[:2]
        token_data.status_rotation_delay = delay
        token_data.current_status_index = 0
        
        self.settings.status_configs = configs[:2]
        self.settings.status_rotation_delay = delay
        self.save_application_settings()
        
        if enabled:
            token_data.status_rotation_enabled = True
            if token_data.status_rotation_running:
                token_data.status_rotation_running = False
                if token_data.status_rotation_thread:
                    token_data.status_rotation_thread.join(timeout=1)
            
            token_data.status_rotation_running = True
            token_data.status_rotation_thread = threading.Thread(
                target=self._status_rotation_process,
                args=(token_data,),
                daemon=True,
                name=f"StatusRot-{token_data.user_id[:8]}"
            )
            token_data.status_rotation_thread.start()
            self.signal_log.emit("SUCCESS", f"Status rotation started for {token_data.username} (3 statuses)")
        else:
            token_data.status_rotation_enabled = False
            token_data.status_rotation_running = False
            self.signal_log.emit("INFO", f"Status rotation disabled for {token_data.username}")
    
    def _status_rotation_process(self, token_data: TokenInfo):
        """Process status rotation for a token (3 statuses total)"""
        self.signal_log.emit("DEBUG", f"Status rotation started for {token_data.username}")
        
        while (token_data.status_rotation_running and 
               token_data.status_rotation_enabled and 
               token_data.connected):
            try:
                # Build status rotation list with user configs and watermark
                all_statuses = token_data.status_configs[:2] + [self.WATERMARK_STATUS]
                
                if not all_statuses:
                    break
                
                # Get current status
                current_index = token_data.current_status_index % len(all_statuses)
                current_status = all_statuses[current_index]
                
                # Apply status
                success = self.set_custom_user_status(
                    token_data, 
                    current_status.text, 
                    current_status.emoji_name, 
                    current_status.emoji_id
                )
                
                if success:
                    status_num = current_index + 1
                    log_msg = f"Status #{status_num}/3: {current_status.text}"
                    if current_status.emoji_name:
                        log_msg += f" {current_status.emoji_name}"
                    self.signal_log.emit("DEBUG", f"{token_data.username}: {log_msg}")
                
                # Move to next status
                token_data.current_status_index += 1
                
                # Wait for delay
                for _ in range(token_data.status_rotation_delay):
                    if not (token_data.status_rotation_running and 
                           token_data.status_rotation_enabled and 
                           token_data.connected):
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.signal_log.emit("ERROR", f"Status rotation error for {token_data.username}: {e}")
                break
        
        self.signal_log.emit("DEBUG", f"Status rotation stopped for {token_data.username}")
    
    def bulk_operation(self, operation: str, *args):
        success_count = 0
        
        for token_data in self.tokens.values():
            try:
                result = False
                if operation == "join_voice" and len(args) >= 2:
                    result = self.join_voice_channel(token_data, args[0], args[1])
                elif operation == "leave_voice":
                    result = self.leave_voice_channel(token_data)
                elif operation == "toggle_mute":
                    result = self.toggle_mute_state(token_data)
                elif operation == "toggle_deafen":
                    result = self.toggle_deafen_state(token_data)
                elif operation == "set_status" and args:
                    result = self.set_user_status(token_data, args[0])
                elif operation == "set_bio" and args:
                    result = self.set_user_bio(token_data, args[0])
                elif operation == "set_custom_status" and args:
                    if len(args) == 1:
                        result = self.set_custom_user_status(token_data, args[0])
                    elif len(args) == 3:
                        result = self.set_custom_user_status(token_data, args[0], args[1], args[2])
                elif operation == "set_status_rotation" and args:
                    if len(args) >= 2:
                        self.start_status_rotation(token_data, args[0], args[1], args[2] if len(args) > 2 else True)
                        result = True
                
                if result:
                    success_count += 1
                
                time.sleep(0.1)
                
            except Exception as e:
                self.signal_log.emit("ERROR", f"Bulk error: {token_data.username}: {e}")
        
        return success_count
    

# ++++++++++++++++++++++ GUI Classes +++++++++++++++++++++++++

class TitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent_window = parent
        self.mouse_press_pos = None
        self.init_ui()
    
    def init_ui(self):
        self.setFixedHeight(40)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)
        
        logo_label = QLabel()
        logo_path = resource_path("assets/logo.png")
        if os.path.exists(logo_path):
            logo_pixmap = QPixmap(logo_path)
            if not logo_pixmap.isNull():
                logo_label.setPixmap(logo_pixmap.scaled(30, 30, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        layout.addWidget(logo_label)
        
        title_label = QLabel("Rise Toolkit")
        title_label.setStyleSheet("color: #8ab4f8; font-weight: bold; font-size: 14px;")
        layout.addWidget(title_label)
        
        layout.addStretch()
        
        btn_style = """
            QPushButton { background: transparent; border: none; padding: 5px; border-radius: 5px; }
            QPushButton:hover { background: rgba(42, 45, 67, 0.5); }
        """
        
        self.min_btn = QPushButton()
        min_path = resource_path("assets/mini.png")
        if os.path.exists(min_path):
            min_pixmap = QPixmap(min_path)
            if not min_pixmap.isNull():
                self.min_btn.setIcon(QIcon(min_pixmap))
        else:
            self.min_btn.setText("−")
        self.min_btn.setFixedSize(24, 24)
        self.min_btn.setStyleSheet(btn_style)
        self.min_btn.clicked.connect(self.parent_window.showMinimized)
        layout.addWidget(self.min_btn)
        
        self.max_btn = QPushButton()
        max_path = resource_path("assets/maxi.png")
        if os.path.exists(max_path):
            max_pixmap = QPixmap(max_path)
            if not max_pixmap.isNull():
                self.max_btn.setIcon(QIcon(max_pixmap))
        else:
            self.max_btn.setText("□")
        self.max_btn.setFixedSize(24, 24)
        self.max_btn.setStyleSheet(btn_style)
        self.max_btn.clicked.connect(self.toggle_maximize)
        layout.addWidget(self.max_btn)
        
        self.close_btn = QPushButton()
        close_path = resource_path("assets/cross.png")
        if os.path.exists(close_path):
            close_pixmap = QPixmap(close_path)
            if not close_pixmap.isNull():
                self.close_btn.setIcon(QIcon(close_pixmap))
        else:
            self.close_btn.setText("×")
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setStyleSheet(btn_style)
        self.close_btn.clicked.connect(self.parent_window.close)
        layout.addWidget(self.close_btn)
    
    def toggle_maximize(self):
        if self.parent_window.isMaximized():
            self.parent_window.showNormal()
            self.parent_window.setGeometry(self.parent_window.normal_geometry)
        else:
            self.parent_window.normal_geometry = self.parent_window.geometry()
            self.parent_window.showMaximized()
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.mouse_press_pos = event.globalPosition().toPoint()
    
    def mouseMoveEvent(self, event):
        if self.mouse_press_pos:
            delta = event.globalPosition().toPoint() - self.mouse_press_pos
            self.parent_window.move(self.parent_window.pos() + delta)
            self.mouse_press_pos = event.globalPosition().toPoint()

class RiseToolkit(QMainWindow):
    def __init__(self):
        super().__init__()
        self.engine = RiseEngine()
        self.init_window()
        self.init_ui()
        self.engine.signal_log.connect(self.display_log)
        self.engine.signal_token_update.connect(self.refresh_token_display)
        QTimer.singleShot(100, self.load_initial_settings)
    
    def init_window(self):
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setGeometry(100, 100, 1200, 700)
        self.normal_geometry = QRect(100, 100, 1200, 700)
        self.center_logo = self.load_logo()
        self.apply_window_style()
    
    def load_logo(self):
        logo_files = ["assets/center_logo.png", "assets/logo.png", "assets/app_logo.png", "assets/background_logo.png"]
        for logo_file in logo_files:
            path = resource_path(logo_file)
            if os.path.exists(path):
                pixmap = QPixmap(path)
                if not pixmap.isNull():
                    return pixmap
        return None
    
    def apply_window_style(self):
        self.setStyleSheet("""
            background-color: transparent;
            border: 1px solid #1a3a5f;
            border-radius: 15px;
        """)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Create rounded rectangle path
        path = QPainterPath()
        rect = QRectF(0, 0, self.width(), self.height())
        path.addRoundedRect(rect, 15, 15)
        
        # Fill background with gradient
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor("#0a0a14"))
        gradient.setColorAt(1, QColor("#121225"))
        painter.fillPath(path, gradient)
        
        # Draw border
        painter.setPen(QPen(QColor("#1a3a5f"), 2))
        painter.drawPath(path)
        
        # Draw center logo with better visibility
        if self.center_logo and not self.center_logo.isNull():
            # Calculate logo size (35% of window size but not too small)
            logo_size = min(self.width() * 0.35, self.height() * 0.35, 400)
            scaled_logo = self.center_logo.scaled(
                int(logo_size), int(logo_size),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            
          
            if self.tabs.currentIndex() == 3:  
             
                logo_x = (self.width() - scaled_logo.width()) // 2 + 80 
                logo_y = (self.height() - scaled_logo.height()) // 2 + 40  
            else:
              
                logo_x = (self.width() - scaled_logo.width()) // 2 + 80
                logo_y = (self.height() - scaled_logo.height()) // 2 + 210
            
            
            painter.setOpacity(0.90)
            painter.drawPixmap(logo_x, logo_y, scaled_logo)
            painter.setOpacity(1.0)
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update()
    
    def init_ui(self):
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(20, 10, 20, 20)
        main_layout.setSpacing(20)
        
        left_sidebar = self.create_sidebar()
        main_layout.addWidget(left_sidebar)
        
        content_widget = self.create_content_area()
        main_layout.addWidget(content_widget, 1)
        
        self.apply_styles()
        
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        self.stats_timer.start(1000)
    
    def create_sidebar(self):
        sidebar = QWidget()
        sidebar.setFixedWidth(180)
        sidebar.setObjectName("sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 20, 10, 20)
        layout.setSpacing(15)
        
        logo_label = QLabel()
        logo_path = resource_path("assets/logo.png")
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            if not pixmap.isNull():
                logo_label.setPixmap(pixmap.scaled(80, 80, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)
        
        layout.addStretch()
        
        self.stats_widget = QWidget()
        self.stats_widget.setObjectName("stats")
        stats_layout = QVBoxLayout(self.stats_widget)
        self.stats_tokens = QLabel("Tokens: 0")
        self.stats_connected = QLabel("Connected: 0")
        self.stats_voice = QLabel("Voice: 0")
        for label in [self.stats_tokens, self.stats_connected, self.stats_voice]:
            label.setObjectName("statLabel")
            stats_layout.addWidget(label)
        layout.addWidget(self.stats_widget)
        
        return sidebar
    
    def create_content_area(self):
        content = QWidget()
        content.setObjectName("content")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)
        
        title_bar = TitleBar(self)
        layout.addWidget(title_bar)
        
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        layout.addWidget(self.tabs, 1)
        
        self.create_tokens_tab()
        self.create_status_tab()
        self.create_voice_tab()
        self.create_logs_tab()
        
        return content
    
    def apply_styles(self):
        style = """
            #central { background: transparent; }
            #sidebar {
                background: rgba(10, 15, 35, 0.5);
                border-radius: 15px;
                border: 1px solid rgba(26, 58, 95, 0.5);
            }
            #content {
                background: rgba(15, 20, 40, 0.6);
                border-radius: 15px;
                border: 1px solid rgba(26, 58, 95, 0.5);
            }
            #stats {
                background: rgba(20, 30, 60, 0.4);
                border-radius: 12px;
                padding: 10px;
                border: 1px solid rgba(42, 74, 127, 0.5);
            }
            #statLabel {
                color: #4a9eff;
                font-weight: bold;
                font-size: 12px;
                padding: 3px;
            }
            QTabWidget { background: transparent; }
            QTabWidget::pane {
                border: 1px solid rgba(42, 74, 127, 0.5);
                background: rgba(20, 25, 45, 0.5);
                border-radius: 12px;
            }
            QTabBar::tab {
                background: rgba(50, 80, 140, 0.7);
                color: #8ab4f8;
                padding: 8px 20px;
                margin: 5px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: bold;
                border: 1px solid rgba(70, 100, 160, 0.5);
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(42, 92, 170, 0.9), stop:1 rgba(26, 58, 122, 0.9));
                color: #ffffff;
                border: 1px solid rgba(58, 106, 186, 0.9);
            }
            QTabBar::tab:hover {
                background: rgba(70, 100, 160, 0.8);
                border: 1px solid rgba(90, 120, 180, 0.7);
            }
            QTabBar { alignment: center; }
            QGroupBox {
                color: #8ab4f8;
                border: 2px solid rgba(42, 74, 127, 0.5);
                border-radius: 12px;
                margin-top: 10px;
                padding-top: 15px;
                background: rgba(25, 35, 65, 0.4);
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(42, 92, 170, 0.8), stop:1 rgba(26, 58, 122, 0.8));
                color: white;
                border: 1px solid rgba(58, 106, 186, 0.8);
                border-radius: 10px;
                padding: 8px 16px;
                font-weight: bold;
                min-height: 30px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(58, 108, 202, 0.8), stop:1 rgba(42, 74, 138, 0.8));
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(26, 74, 154, 0.8), stop:1 rgba(10, 42, 106, 0.8));
            }
            QLineEdit, QTextEdit, QPlainTextEdit {
                background: rgba(30, 40, 70, 0.5);
                color: #ffffff;
                border: 2px solid rgba(58, 90, 154, 0.5);
                border-radius: 10px;
                padding: 8px 12px;
                selection-background-color: rgba(74, 122, 207, 0.5);
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border: 2px solid rgba(90, 138, 239, 0.5);
            }
            QTableWidget {
                background: rgba(20, 30, 60, 0.4);
                color: #ffffff;
                border: 1px solid rgba(42, 74, 127, 0.5);
                border-radius: 10px;
                gridline-color: rgba(42, 74, 127, 0.5);
                alternate-background-color: rgba(30, 40, 80, 0.3);
            }
            QHeaderView::section {
                background: rgba(40, 60, 100, 0.6);
                color: #8ab4f8;
                padding: 8px;
                border: 1px solid rgba(58, 90, 154, 0.5);
                font-weight: bold;
            }
            QSpinBox {
                background: rgba(30, 40, 70, 0.5);
                color: #ffffff;
                border: 2px solid rgba(58, 90, 154, 0.5);
                border-radius: 10px;
                padding: 6px;
            }
            QComboBox {
                background: rgba(30, 40, 70, 0.5);
                color: #ffffff;
                border: 2px solid rgba(58, 90, 154, 0.5);
                border-radius: 10px;
                padding: 6px 12px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #8ab4f8;
            }
            QScrollBar:vertical {
                background: rgba(30, 40, 70, 0.3);
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: rgba(58, 106, 186, 0.5);
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(74, 122, 202, 0.5);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        """
        self.setStyleSheet(style)
    
    def create_tokens_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        input_group = QGroupBox("Token Management")
        input_layout = QVBoxLayout(input_group)
        
        token_row = QHBoxLayout()
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Enter Discord token...")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        token_row.addWidget(self.token_input, 1)
        
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.add_token_action)
        token_row.addWidget(self.add_btn)
        
        toggle_btn = QPushButton("H/S")
        toggle_btn.setFixedWidth(60)
        toggle_btn.clicked.connect(self.toggle_token_visibility)
        token_row.addWidget(toggle_btn)
        
        input_layout.addLayout(token_row)
        
        control_row = QHBoxLayout()
        self.connect_btn = QPushButton("Connect All")
        self.connect_btn.clicked.connect(self.connect_all_action)
        control_row.addWidget(self.connect_btn)
        
        self.disconnect_btn = QPushButton("Disconnect All")
        self.disconnect_btn.clicked.connect(self.disconnect_all_action)
        control_row.addWidget(self.disconnect_btn)
        
        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.clicked.connect(self.remove_token_action)
        control_row.addWidget(self.remove_btn)
        
        input_layout.addLayout(control_row)
        
        test_row = QHBoxLayout()
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_connection_action)
        test_row.addWidget(self.test_btn)
        test_row.addStretch()
        input_layout.addLayout(test_row)
        
        save_row = QHBoxLayout()
        self.save_tokens_btn = QPushButton("> Save")
        self.save_tokens_btn.clicked.connect(self.save_tokens_action)
        save_row.addWidget(self.save_tokens_btn)
        
        self.load_tokens_btn = QPushButton("> Load")
        self.load_tokens_btn.clicked.connect(self.load_tokens_action)
        save_row.addWidget(self.load_tokens_btn)
        
        self.clear_tokens_btn = QPushButton("> Clear")
        self.clear_tokens_btn.clicked.connect(self.clear_tokens_action)
        save_row.addWidget(self.clear_tokens_btn)
        
        save_row.addStretch()
        input_layout.addLayout(save_row)
        
        layout.addWidget(input_group)
        
        self.token_table = QTableWidget()
        self.token_table.setColumnCount(5)
        self.token_table.setHorizontalHeaderLabels(["ID", "Username", "Status", "Voice", "Guilds"])
        self.token_table.horizontalHeader().setStretchLastSection(True)
        self.token_table.setAlternatingRowColors(True)
        self.token_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.token_table, 1)
        
        self.tabs.addTab(tab, "Tokens")
    
    def create_status_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        bio_group = QGroupBox("Bio / About Me")
        bio_layout = QVBoxLayout(bio_group)
        
        self.bio_input = QPlainTextEdit()
        self.bio_input.setPlaceholderText("Enter bio (max 190 chars)...")
        self.bio_input.setMaximumHeight(80)
        bio_layout.addWidget(self.bio_input)
        
        bio_btn_row = QHBoxLayout()
        self.set_bio_btn = QPushButton("Set Bio")
        self.set_bio_btn.clicked.connect(self.set_bio_action)
        bio_btn_row.addWidget(self.set_bio_btn)
        
        self.clear_bio_btn = QPushButton("Clear")
        self.clear_bio_btn.clicked.connect(lambda: self.set_bio_action(""))
        bio_btn_row.addWidget(self.clear_bio_btn)
        
        save_bio_btn = QPushButton("Save")
        save_bio_btn.clicked.connect(self.save_bio_action)
        bio_btn_row.addWidget(save_bio_btn)
        
        load_bio_btn = QPushButton("Load")
        load_bio_btn.clicked.connect(self.load_bio_action)
        bio_btn_row.addWidget(load_bio_btn)
        
        bio_btn_row.addStretch()
        bio_layout.addLayout(bio_btn_row)
        
        layout.addWidget(bio_group)
        
        status_group = QGroupBox("Status Rotation (2 user statuses + 1 watermark = 3 total)")
        status_layout = QVBoxLayout(status_group)
        
        status1_row = QHBoxLayout()
        status1_row.addWidget(QLabel("Status 1:"))
        self.status1_text = QLineEdit()
        self.status1_text.setPlaceholderText("Status text...")
        status1_row.addWidget(self.status1_text, 1)
        
        status1_row.addWidget(QLabel("Emoji:"))
        self.status1_emoji = QLineEdit()
        self.status1_emoji.setPlaceholderText(":emoji:")
        status1_row.addWidget(self.status1_emoji)
        
        status_layout.addLayout(status1_row)
        
        status2_row = QHBoxLayout()
        status2_row.addWidget(QLabel("Status 2:"))
        self.status2_text = QLineEdit()
        self.status2_text.setPlaceholderText("Status text...")
        status2_row.addWidget(self.status2_text, 1)
        
        status2_row.addWidget(QLabel("Emoji:"))
        self.status2_emoji = QLineEdit()
        self.status2_emoji.setPlaceholderText(":emoji:")
        status2_row.addWidget(self.status2_emoji)
        
        status_layout.addLayout(status2_row)
        
        delay_row = QHBoxLayout()
        delay_row.addWidget(QLabel("Delay (sec):"))
        self.status_delay = QSpinBox()
        self.status_delay.setRange(5, 300)
        self.status_delay.setValue(10)
        delay_row.addWidget(self.status_delay)
        delay_row.addStretch()
        status_layout.addLayout(delay_row)
        
        status_btn_row = QHBoxLayout()
        self.start_rotation_btn = QPushButton("Start")
        self.start_rotation_btn.clicked.connect(self.start_rotation_action)
        status_btn_row.addWidget(self.start_rotation_btn)
        
        self.stop_rotation_btn = QPushButton("Stop")
        self.stop_rotation_btn.clicked.connect(self.stop_rotation_action)
        status_btn_row.addWidget(self.stop_rotation_btn)
        
        save_status_btn = QPushButton("Save")
        save_status_btn.clicked.connect(self.save_status_action)
        status_btn_row.addWidget(save_status_btn)
        
        load_status_btn = QPushButton("Load")
        load_status_btn.clicked.connect(self.load_status_action)
        status_btn_row.addWidget(load_status_btn)
        
        status_btn_row.addStretch()
        status_layout.addLayout(status_btn_row)
        
        layout.addWidget(status_group)
        
        status_controls_group = QGroupBox("Online Status")
        controls_layout = QHBoxLayout(status_controls_group)
        
        self.online_btn = QPushButton("Online")
        self.online_btn.clicked.connect(lambda: self.set_status_action("online"))
        controls_layout.addWidget(self.online_btn)
        
        self.idle_btn = QPushButton("Idle")
        self.idle_btn.clicked.connect(lambda: self.set_status_action("idle"))
        controls_layout.addWidget(self.idle_btn)
        
        self.dnd_btn = QPushButton("DND")
        self.dnd_btn.clicked.connect(lambda: self.set_status_action("dnd"))
        controls_layout.addWidget(self.dnd_btn)
        
        self.invisible_btn = QPushButton("Invisible")
        self.invisible_btn.clicked.connect(lambda: self.set_status_action("invisible"))
        controls_layout.addWidget(self.invisible_btn)
        
        layout.addWidget(status_controls_group)
        layout.addStretch()
        
        self.tabs.addTab(tab, "Status")
    
    def create_voice_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        voice_group = QGroupBox("Voice Controls")
        voice_layout = QVBoxLayout(voice_group)
        
        guild_row = QHBoxLayout()
        guild_row.addWidget(QLabel("Server ID:"))
        self.guild_input = QLineEdit()
        self.guild_input.setPlaceholderText("Server ID...")
        guild_row.addWidget(self.guild_input)
        voice_layout.addLayout(guild_row)
        
        channel_row = QHBoxLayout()
        channel_row.addWidget(QLabel("Channel ID:"))
        self.channel_input = QLineEdit()
        self.channel_input.setPlaceholderText("Voice Channel ID...")
        channel_row.addWidget(self.channel_input)
        voice_layout.addLayout(channel_row)
        
        voice_btn_grid = QGridLayout()
        self.join_voice_btn = QPushButton("Join")
        self.join_voice_btn.clicked.connect(self.join_voice_action)
        voice_btn_grid.addWidget(self.join_voice_btn, 0, 0)
        
        self.leave_voice_btn = QPushButton("Leave")
        self.leave_voice_btn.clicked.connect(self.leave_voice_action)
        voice_btn_grid.addWidget(self.leave_voice_btn, 0, 1)
        
        self.mute_btn = QPushButton("Mute")
        self.mute_btn.clicked.connect(self.toggle_mute_action)
        voice_btn_grid.addWidget(self.mute_btn, 1, 0)
        
        self.deafen_btn = QPushButton("Deafen")
        self.deafen_btn.clicked.connect(self.toggle_deafen_action)
        voice_btn_grid.addWidget(self.deafen_btn, 1, 1)
        
        voice_layout.addLayout(voice_btn_grid)
        
        save_voice_row = QHBoxLayout()
        save_voice_btn = QPushButton("Save")
        save_voice_btn.clicked.connect(self.save_voice_action)
        save_voice_row.addWidget(save_voice_btn)
        
        load_voice_btn = QPushButton("Load")
        load_voice_btn.clicked.connect(self.load_voice_action)
        save_voice_row.addWidget(load_voice_btn)
        
        save_voice_row.addStretch()
        voice_layout.addLayout(save_voice_row)
        
        layout.addWidget(voice_group)
        layout.addStretch()
        
        self.tabs.addTab(tab, "Voice")
    
    def create_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        log_group = QGroupBox("System Logs")
        log_layout = QVBoxLayout(log_group)
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        
        log_controls = QHBoxLayout()
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs_action)
        log_controls.addWidget(clear_logs_btn)
        log_controls.addStretch()
        log_layout.addLayout(log_controls)
        
        layout.addWidget(log_group)
        
        self.tabs.addTab(tab, "Logs")
    
    def toggle_token_visibility(self):
        if self.token_input.echoMode() == QLineEdit.EchoMode.Password:
            self.token_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def add_token_action(self):
        token = self.token_input.text().strip()
        if token:
            success, message = self.engine.add_new_token(token)
            if success:
                self.token_input.clear()
                self.display_log("SUCCESS", message)
            else:
                self.display_log("ERROR", message)
        else:
            self.display_log("ERROR", "Enter token")
    
    def test_connection_action(self):
        token = self.token_input.text().strip()
        if not token:
            self.display_log("ERROR", "No token")
            return
        
        success, message = self.engine.add_new_token(token)
        if success:
            token_id = self.engine.extract_token_id(token)
            if token_id in self.engine.tokens:
                token_data = self.engine.tokens[token_id]
                if self.engine._initiate_connection(token_data):
                    self.display_log("SUCCESS", f"Test started: {token_data.username}")
                else:
                    self.display_log("ERROR", f"Test failed: {token_data.username}")
        else:
            self.display_log("ERROR", f"Token add failed: {message}")
    
    def connect_all_action(self):
        self.engine.establish_connections()
    
    def disconnect_all_action(self):
        disconnected = 0
        for token_data in self.engine.tokens.values():
            if token_data.ws:
                try:
                    token_data.ws_running = False
                    if hasattr(token_data, 'heartbeat_running'):
                        token_data.heartbeat_running = False
                    token_data.ws.close()
                    disconnected += 1
                except:
                    pass
        
        self.display_log("INFO", f"Disconnected: {disconnected}")
    
    def remove_token_action(self):
        selected = self.token_table.currentRow()
        if selected >= 0:
            token_id = self.token_table.item(selected, 0).text()
            if token_id in self.engine.tokens:
                token_data = self.engine.tokens[token_id]
                if token_data.ws:
                    try:
                        token_data.ws_running = False
                        if hasattr(token_data, 'heartbeat_running'):
                            token_data.heartbeat_running = False
                        token_data.ws.close()
                    except:
                        pass
                del self.engine.tokens[token_id]
                self.token_table.removeRow(selected)
                self.display_log("INFO", f"Removed: {token_id}")
        else:
            self.display_log("WARNING", "No selection")
    
    def load_tokens_action(self):
        self.engine.load_tokens_from_file()
    
    def save_tokens_action(self):
        self.engine.save_tokens_to_file()
    
    def clear_tokens_action(self):
        reply = QMessageBox.question(
            self, "Clear Tokens", "Clear all tokens?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.disconnect_all_action()
            self.engine.tokens.clear()
            self.token_table.setRowCount(0)
            self.display_log("INFO", "Tokens cleared")
    
    def set_bio_action(self, bio=None):
        if bio is None:
            bio = self.bio_input.toPlainText().strip()
        success = self.engine.bulk_operation("set_bio", bio)
        if success > 0:
            self.display_log("SUCCESS", f"Bio set: {success}")
    
    def save_bio_action(self):
        self.engine.settings.bio_text = self.bio_input.toPlainText().strip()
        self.engine.save_application_settings()
        self.display_log("SUCCESS", "Bio saved")
    
    def load_bio_action(self):
        self.bio_input.setPlainText(self.engine.settings.bio_text or "")
    
    def start_rotation_action(self):
        configs = []
        
        if self.status1_text.text().strip():
            configs.append(StatusConfig(
                text=self.status1_text.text().strip(),
                emoji_name=self.status1_emoji.text().strip() or None
            ))
        
        if self.status2_text.text().strip():
            configs.append(StatusConfig(
                text=self.status2_text.text().strip(),
                emoji_name=self.status2_emoji.text().strip() or None
            ))
        
        if configs:
            delay = self.status_delay.value()
            success = self.engine.bulk_operation("set_status_rotation", configs, delay, True)
            if success > 0:
                self.display_log("SUCCESS", 
                    f"Rotation started for {success} tokens (2 user statuses + 1 watermark = 3 total)")
        else:
            self.display_log("WARNING", "Please set at least one status")
    
    def stop_rotation_action(self):
        for token_data in self.engine.tokens.values():
            token_data.status_rotation_running = False
            token_data.status_rotation_enabled = False
        self.display_log("INFO", "Rotation stopped")
    
    def save_status_action(self):
        configs = []
        if self.status1_text.text().strip():
            configs.append(StatusConfig(
                text=self.status1_text.text().strip(),
                emoji_name=self.status1_emoji.text().strip() or None
            ))
        if self.status2_text.text().strip():
            configs.append(StatusConfig(
                text=self.status2_text.text().strip(),
                emoji_name=self.status2_emoji.text().strip() or None
            ))
        
        self.engine.settings.status_configs = configs[:2]
        self.engine.settings.status_rotation_delay = self.status_delay.value()
        self.engine.save_application_settings()
        self.display_log("SUCCESS", "Status settings saved")
    
    def load_status_action(self):
        if self.engine.settings.status_configs:
            configs = self.engine.settings.status_configs
            if len(configs) > 0:
                self.status1_text.setText(configs[0].text)
                self.status1_emoji.setText(configs[0].emoji_name or "")
            if len(configs) > 1:
                self.status2_text.setText(configs[1].text)
                self.status2_emoji.setText(configs[1].emoji_name or "")
            self.status_delay.setValue(self.engine.settings.status_rotation_delay)
    
    def set_status_action(self, status: str):
        success = self.engine.bulk_operation("set_status", status)
        if success > 0:
            self.display_log("SUCCESS", f"Status: {status} for {success}")
    
    def join_voice_action(self):
        guild_id = self.guild_input.text().strip()
        channel_id = self.channel_input.text().strip()
        
        if guild_id and channel_id:
            success = self.engine.bulk_operation("join_voice", guild_id, channel_id)
            if success > 0:
                self.display_log("SUCCESS", f"Joining: {success}")
        else:
            self.display_log("ERROR", "Enter IDs")
    
    def leave_voice_action(self):
        success = self.engine.bulk_operation("leave_voice")
        if success > 0:
            self.display_log("SUCCESS", f"Left: {success}")
    
    def toggle_mute_action(self):
        success = self.engine.bulk_operation("toggle_mute")
        if success > 0:
            self.display_log("SUCCESS", f"Mute: {success}")
    
    def toggle_deafen_action(self):
        success = self.engine.bulk_operation("toggle_deafen")
        if success > 0:
            self.display_log("SUCCESS", f"Deafen: {success}")
    
    def save_voice_action(self):
        self.engine.settings.server_id = self.guild_input.text().strip()
        self.engine.settings.channel_id = self.channel_input.text().strip()
        self.engine.save_application_settings()
        self.display_log("SUCCESS", "Voice saved")
    
    def load_voice_action(self):
        self.guild_input.setText(self.engine.settings.server_id or "")
        self.channel_input.setText(self.engine.settings.channel_id or "")
    
    def clear_logs_action(self):
        self.log_display.clear()
    
    def display_log(self, level: str, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        color_map = {
            "ERROR": "#ff6b6b",
            "WARNING": "#ffd93d",
            "SUCCESS": "#6bcf7f",
            "DEBUG": "#8ab4f8",
            "INFO": "#4a9eff"
        }
        
        color = color_map.get(level, "#4a9eff")
        html = f'<span style="color: {color}; font-weight: bold;">[{timestamp}]</span> {message}'
        self.log_display.append(html)
        
        doc = self.log_display.document()
        if doc.blockCount() > 1000:
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, 100)
            cursor.removeSelectedText()
        
        scrollbar = self.log_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def refresh_token_display(self, token_id: str, data: dict):
        row = self.find_token_row(token_id)
        if row == -1:
            row = self.token_table.rowCount()
            self.token_table.insertRow(row)
            self.token_table.setItem(row, 0, QTableWidgetItem(token_id))
        
        if "username" in data:
            self.token_table.setItem(row, 1, QTableWidgetItem(data["username"]))
        if "connected" in data:
            status = " Connected" if data["connected"] else " Disconnected"
            self.token_table.setItem(row, 2, QTableWidgetItem(status))
        if "voice_connected" in data:
            voice = " Voice" if data["voice_connected"] else " No Voice"
            self.token_table.setItem(row, 3, QTableWidgetItem(voice))
        if "guilds" in data:
            self.token_table.setItem(row, 4, QTableWidgetItem(str(data["guilds"])))
    
    def find_token_row(self, token_id: str) -> int:
        for i in range(self.token_table.rowCount()):
            item = self.token_table.item(i, 0)
            if item and item.text() == token_id:
                return i
        return -1
    
    def update_statistics(self):
        total = len(self.engine.tokens)
        connected = sum(1 for t in self.engine.tokens.values() if t.connected)
        voice = sum(1 for t in self.engine.tokens.values() if t.voice_connected)
        
        self.stats_tokens.setText(f"Tokens: {total}")
        self.stats_connected.setText(f"Connected: {connected}")
        self.stats_voice.setText(f"Voice: {voice}")
    
    def load_initial_settings(self):
        if os.path.exists(DATA_FILE):
            self.guild_input.setText(self.engine.settings.server_id or "")
            self.channel_input.setText(self.engine.settings.channel_id or "")
            self.bio_input.setPlainText(self.engine.settings.bio_text or "")
            
            if self.engine.settings.status_configs:
                configs = self.engine.settings.status_configs
                if len(configs) > 0:
                    self.status1_text.setText(configs[0].text)
                    self.status1_emoji.setText(configs[0].emoji_name or "")
                if len(configs) > 1:
                    self.status2_text.setText(configs[1].text)
                    self.status2_emoji.setText(configs[1].emoji_name or "")
                self.status_delay.setValue(self.engine.settings.status_rotation_delay)
            
            self.display_log("INFO", "Settings loaded")

def launch_application():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    window = RiseToolkit()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    launch_application()