import hashlib
import os
import random
import sys
import customtkinter as ctk
from aegis import AegisCore

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

INACTIVITY_TIMEOUT_MS = 180000  # 3 minutes avant purge automatique
CLIPBOARD_CLEAR_MS = 10000      # 10 secondes avant vidage du presse-papier

DECOY_SCENARIOS = [
    {
        "title": "📋 TÂCHES CHANTIER & RÉNOVATION MAISON",
        "items": [
            "[ ] Passer chez Point.P : 4 sacs de ciment PRB, 10 rails R48, 1 rouleau laine de verre 100mm",
            "[ ] Relancer l'artisan pour le devis d'étanchéité terrasse (rappel avant vendredi)",
            "[ ] Valider la commande Castorama : Ponceuse girafe giraflex + 20 disques grain 80/120"
        ]
    },
    {
        "title": "🛒 COURSES HEBDOMADAIRES & PARAPHARMACIE",
        "items": [
            "[ ] Carrefour : Lait d'amande Bio, Huile d'olive Vierge Extra 2L, Filets de poulet x6",
            "[ ] Pharmacie : Bétadine, Pansements étanches grand format, Comprégies Vitamine C 1000"
        ]
    }
]

class SessionPinManager:
    def __init__(self, true_pin: str = "1234", decoy_pin: str = "5555"):
        self._true_pin_hash = self._hash_pin(true_pin)
        self._decoy_pin_hash = self._hash_pin(decoy_pin)

    def _hash_pin(self, pin: str) -> str:
        return hashlib.sha256(f"AEGIS_SALT_{pin}".encode()).hexdigest()

    def set_new_pins(self, new_true_pin: str, new_decoy_pin: str):
        self._true_pin_hash = self._hash_pin(new_true_pin)
        self._decoy_pin_hash = self._hash_pin(new_decoy_pin)

    def evaluate_entry(self, entered_pin: str) -> str:
        entered_hash = self._hash_pin(entered_pin.strip())
        if entered_hash == self._true_pin_hash:
            return "VALID"
        elif entered_hash == self._decoy_pin_hash:
            return "DECOY"
        else:
            return "PANIC"

class DecoyView(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True, padx=20, pady=20)
        scenario = random.choice(DECOY_SCENARIOS)

        ctk.CTkLabel(self, text=scenario["title"], font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(10, 15))
        textbox = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Arial", size=13), fg_color="#1e1e1e", text_color="#dcdcdc")
        textbox.pack(fill="both", expand=True)

        for item in scenario["items"]:
            textbox.insert("end", item + "\n\n")

class ChangePinDialog(ctk.CTkToplevel):
    def __init__(self, parent, pin_manager):
        super().__init__(parent)
        self.pin_manager = pin_manager
        self.title("Modification des Codes PIN")
        self.geometry("380x300")
        self.resizable(False, False)
        self.grab_set()

        ctk.CTkLabel(self, text="MODIFIER LES CODES DE SESSION", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(15, 10))
        self.old_pin_entry = ctk.CTkEntry(self, placeholder_text="PIN Principal Actuel", show="*", width=250)
        self.old_pin_entry.pack(pady=5)

        self.new_true_pin_entry = ctk.CTkEntry(self, placeholder_text="Nouveau PIN Principal (C2)", show="*", width=250)
        self.new_true_pin_entry.pack(pady=5)

        self.new_decoy_pin_entry = ctk.CTkEntry(self, placeholder_text="Nouveau PIN Leurre (Decoy)", show="*", width=250)
        self.new_decoy_pin_entry.pack(pady=5)

        self.status_label = ctk.CTkLabel(self, text="", text_color="#FF3333")
        self.status_label.pack(pady=2)

        ctk.CTkButton(self, text="Valider le Changement", command=self.apply_pin_change, width=180).pack(pady=10)

    def apply_pin_change(self):
        old_pin = self.old_pin_entry.get().strip()
        new_true = self.new_true_pin_entry.get().strip()
        new_decoy = self.new_decoy_pin_entry.get().strip()

        if self.pin_manager.evaluate_entry(old_pin) != "VALID":
            self.status_label.configure(text="PIN actuel incorrect.")
            return

        if not new_true or not new_decoy or new_true == new_decoy:
            self.status_label.configure(text="Les nouveaux PINs doivent être distincts.")
            return

        self.pin_manager.set_new_pins(new_true, new_decoy)
        self.destroy()

class LoginDialog(ctk.CTkToplevel):
    def __init__(self, parent, aegis_core):
        super().__init__(parent)
        self.aegis = aegis_core
        self.parent = parent
        
        self.title("Authentification AEGIS")
        self.geometry("350x220")
        self.resizable(False, False)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        ctk.CTkLabel(self, text="Entrez votre PIN d'accès", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(20, 10))

        self.pin_entry = ctk.CTkEntry(self, show="*", width=200, justify="center", font=ctk.CTkFont(size=18))
        self.pin_entry.pack(pady=10)
        self.pin_entry.bind("<Return>", lambda e: self.validate_pin())

        ctk.CTkButton(self, text="Déverrouiller", command=self.validate_pin, width=150).pack(pady=15)

    def validate_pin(self):
        entered_pin = self.pin_entry.get()
        result = self.parent.pin_manager.evaluate_entry(entered_pin)

        if result == "VALID":
            self.destroy()
            self.parent.load_tactical_c2()
        elif result == "DECOY":
            self.destroy()
            self.parent.load_decoy_view()
        else:
            self.aegis.emergency_purge()
            self.parent.destroy()
            sys.exit(0)

    def on_close(self):
        self.aegis.emergency_purge()
        self.parent.destroy()
        sys.exit(0)

class AegisDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.aegis = AegisCore()
        self.pin_manager = SessionPinManager()
        self.inactivity_timer = None

        self.title("AEGIS Terminal")
        self.geometry("980x820")
        self.resizable(False, False)

        self.withdraw()
        self.login_dialog = LoginDialog(self, self.aegis)

    def reset_inactivity_timer(self, event=None):
        """Réinitialise le Dead Man's Switch d'inactivité à chaque action utilisateur."""
        if self.inactivity_timer:
            self.after_cancel(self.inactivity_timer)
        self.inactivity_timer = self.after(INACTIVITY_TIMEOUT_MS, self.on_inactivity_timeout)

    def on_inactivity_timeout(self):
        """Action déclenchée après 3 minutes d'inactivité totale."""
        if hasattr(self, 'log_text'):
            self.append_log("[🚨 DEAD MAN'S SWITCH] Inactivité détectée. Purge automatique...")
        self.on_emergency_purge()

    def secure_copy_to_clipboard(self, content: str):
        """Injecte un secret dans le presse-papier et planifie sa destruction après 10 sec."""
        self.clipboard_clear()
        self.clipboard_append(content)
        self.append_log("[SEC] Donnée copiée dans le presse-papier (Auto-destruction dans 10s).")
        self.after(CLIPBOARD_CLEAR_MS, self.clear_clipboard)

    def clear_clipboard(self):
        self.clipboard_clear()
        self.append_log("[SEC] Presse-papier système totalement purgé.")

    def load_decoy_view(self):
        self.deiconify()
        self.title("Bloc-Notes Personnel")
        DecoyView(self)

    def load_tactical_c2(self):
        self.deiconify()
        self.title("AEGIS C2 - Tactical Encryption & Steganography Terminal")

        # Armement de l'intercepteur d'inactivité utilisateur (Souris & Clavier)
        self.bind_all("<Key>", self.reset_inactivity_timer)
        self.bind_all("<Button>", self.reset_inactivity_timer)
        self.bind_all("<Motion>", self.reset_inactivity_timer)
        self.reset_inactivity_timer()
        
        # Header Status Bar
        self.header_frame = ctk.CTkFrame(self, height=50, corner_radius=0)
        self.header_frame.pack(fill="x", side="top", padx=0, pady=0)
        
        ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ AEGIS TACTICAL C2 SYSTEM", 
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left", padx=20, pady=10)
        
        ctk.CTkButton(
            self.header_frame,
            text="🚨 PURGE D'URGENCE (ZEROIZE)",
            command=self.on_emergency_purge,
            fg_color="#8b0000",
            hover_color="#550000",
            width=200
        ).pack(side="right", padx=10, pady=10)

        ctk.CTkButton(
            self.header_frame,
            text="🔑 CHANGER PIN",
            command=self.on_change_pin,
            fg_color="#4a5568",
            hover_color="#2d3748",
            width=120
        ).pack(side="right", padx=5, pady=10)
        
        # Main Body
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Section 1 : Identity Management
        self.id_box = ctk.CTkFrame(self.main_frame)
        self.id_box.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(
            self.id_box, 
            text="1. GESTION DE L'IDENTITÉ & MNÉMONIQUE BIP-39", 
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=10, pady=(6, 2))
        
        btn_row = ctk.CTkFrame(self.id_box, fg_color="transparent")
        btn_row.pack(anchor="w", padx=10, pady=3)

        ctk.CTkButton(
            btn_row, 
            text="GÉNÉRER CLÉ HORS-LIGNE", 
            command=self.on_generate_keys,
            fg_color="#1f538d", 
            hover_color="#14375e"
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, 
            text="📋 COPIER MNÉMONIQUE (SÉCURISÉ)", 
            command=lambda: self.secure_copy_to_clipboard(self.mnemonic_entry.get()),
            fg_color="#2b2b2b", 
            hover_color="#3a3a3a"
        ).pack(side="left")
        
        self.mnemonic_entry = ctk.CTkEntry(self.id_box, placeholder_text="Phrase mnémonique générée...", width=920)
        self.mnemonic_entry.pack(padx=10, pady=3)
        
        self.hash_entry = ctk.CTkEntry(self.id_box, placeholder_text="Empreinte Publique unique (Public Hash)...", width=920, text_color="#00FF66")
        self.hash_entry.pack(padx=10, pady=(3, 8))
        
        # Section 2 : Steganography
        self.stego_box = ctk.CTkFrame(self.main_frame)
        self.stego_box.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(
            self.stego_box, 
            text="2. SAUVEGARDE STÉGANOGRAPHIQUE (DROWNING PAPER BACKUP)", 
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=10, pady=(6, 2))
        
        stego_btn_frame = ctk.CTkFrame(self.stego_box, fg_color="transparent")
        stego_btn_frame.pack(fill="x", padx=10, pady=3)
        
        ctk.CTkButton(
            stego_btn_frame, 
            text="NOYER LE MNÉMONIQUE", 
            command=self.on_stego_hide,
            fg_color="#6f42c1", 
            hover_color="#593196",
            width=180
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            stego_btn_frame, 
            text="EXTRAIRE LE MNÉMONIQUE", 
            command=self.on_stego_extract,
            fg_color="#d63384", 
            hover_color="#a82365",
            width=180
        ).pack(side="left")

        self.stego_entry = ctk.CTkEntry(self.stego_box, placeholder_text="Texte stéganographié...", width=920, text_color="#FFD700")
        self.stego_entry.pack(padx=10, pady=(3, 8))

        # Section 3 : Encrypted Messaging Area
        self.msg_box = ctk.CTkFrame(self.main_frame)
        self.msg_box.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(
            self.msg_box, 
            text="3. CANAL DE MESSAGERIE CHIFFRÉE (RATCHET / CHACHA20-POLY1305)", 
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=10, pady=(6, 2))
        
        self.input_msg = ctk.CTkEntry(self.msg_box, placeholder_text="Entrez votre message tactique...", width=750)
        self.input_msg.pack(side="left", padx=10, pady=6)
        
        ctk.CTkButton(
            self.msg_box, 
            text="CHIFFRER & ENVOYER", 
            command=self.on_send_message,
            fg_color="#008037", 
            hover_color="#005c27",
            width=150
        ).pack(side="right", padx=10, pady=6)
        
        # Section 4 : Console Logs
        self.log_box = ctk.CTkFrame(self.main_frame)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        
        ctk.CTkLabel(
            self.log_box, 
            text="4. FLUX DE DÉCRYPTAGE & JOURNAUX SYSTÈME", 
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=10, pady=(6, 2))
        
        self.log_text = ctk.CTkTextbox(self.log_box, font=ctk.CTkFont(family="Consolas", size=11), text_color="#00FF66", fg_color="#000000")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(2, 8))
        
        self.append_log("[INFO] Moteur AEGIS v1.0 connecté.")
        self.append_log("[INFO] Dead Man's Switch (3 min) & Auto-Clear Presse-Papier armés.")

    def append_log(self, text: str):
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")

    def on_generate_keys(self):
        phrase = self.aegis.generate_mnemonic()
        if phrase:
            hash_id = self.aegis.derive_identity_hash(phrase)
            self.mnemonic_entry.delete(0, "end")
            self.mnemonic_entry.insert(0, phrase)
            self.hash_entry.delete(0, "end")
            self.hash_entry.insert(0, hash_id if hash_id else "")
            self.append_log(f"[CRYPTO] Clefs Ed25519/X25519 générées.")
            self.append_log(f"[IDENTITY] Empreinte : {hash_id}")

    def on_stego_hide(self):
        phrase = self.mnemonic_entry.get()
        if not phrase:
            self.append_log("[WARN] Aucun mnémonique à dissimuler.")
            return

        cover_template = "RAPPORT TACTIQUE - R.A.S. - DÉPLOIEMENT CONFORME AUX DIRECTIVES D'OPÉRATION."
        stego_text = self.aegis.stegano_hide(phrase, cover_template)
        if stego_text:
            self.stego_entry.delete(0, "end")
            self.stego_entry.insert(0, stego_text)
            self.append_log("[STEGANO] Mnémonique noyé dans le texte de couverture.")

    def on_stego_extract(self):
        stego_text = self.stego_entry.get()
        if not stego_text:
            self.append_log("[WARN] Aucun texte stéganographié à analyser.")
            return

        extracted = self.aegis.stegano_extract(stego_text)
        if extracted:
            self.append_log(f"[STEGANO] Mnémonique extrait : '{extracted}'")
        else:
            self.append_log("[STEGANO ERROR] Échec de l'extraction ou données corrompues.")

    def on_send_message(self):
        plaintext = self.input_msg.get()
        hash_id = self.hash_entry.get()
        if not plaintext or not hash_id:
            self.append_log("[WARN] Identité ou message manquant.")
            return

        encrypted_hex = self.aegis.encrypt_message(hash_id, plaintext)
        self.append_log(f"\n[EMISSION] Message : '{plaintext}'")
        self.append_log(f"[CHIFFRÉ] Payload Hex : {encrypted_hex}")
        
        decrypted_text = self.aegis.decrypt_message(hash_id, encrypted_hex)
        self.append_log(f"[RECEPTION] Message restitué : '{decrypted_text}'")
        self.input_msg.delete(0, "end")

    def on_change_pin(self):
        ChangePinDialog(self, self.pin_manager)

    def on_emergency_purge(self):
        self.mnemonic_entry.delete(0, "end")
        self.hash_entry.delete(0, "end")
        self.stego_entry.delete(0, "end")
        self.input_msg.delete(0, "end")
        self.log_text.delete("1.0", "end")
        self.clear_clipboard()

        if self.aegis.emergency_purge():
            self.destroy()
            sys.exit(0)

if __name__ == "__main__":
    app = AegisDashboard()
    app.mainloop()