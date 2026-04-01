

import json
import os


class Settings:
    def __init__(self, file_path="/dev/shm/settings.json"):
        self.file_path = file_path
        self.default = {
            "show_reg": [],
            "show_stack": "",
            "theme": "light"
        }
        self._data = self._load()

    def _load(self):
        if not os.path.exists(self.file_path):
            self._save(self.default)
            return self.default.copy()

        with open(self.file_path, "r") as f:
            data = json.load(f)

        # merge default
        for k, v in self.default.items():
            if k not in data:
                data[k] = v

        return data

    def _save(self, data):
        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=4)

    # ========================
    # BASIC
    # ========================
    def get(self, key):
        return self._data.get(key, self.default.get(key))

    def set(self, key, value):
        self._data[key] = value
        self._save(self._data)

    # ========================
    # LIST MANAGEMENT (show_reg)
    # ========================
    def add_to_list(self, key, value):
        if key not in self._data or not isinstance(self._data[key], list):
            raise ValueError(f"{key} is not a list")

        if value not in self._data[key]:
            self._data[key].append(value)
            self._save(self._data)

    def remove_from_list(self, key, value):
        if key not in self._data or not isinstance(self._data[key], list):
            raise ValueError(f"{key} is not a list")

        if value in self._data[key]:
            self._data[key].remove(value)
            self._save(self._data)

    def exists_in_list(self, key, value):
        return value in self._data.get(key, [])
