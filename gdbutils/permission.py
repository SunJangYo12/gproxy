import enum

class Permission(enum.Flag):
    """GEF representation of Linux permission."""
    NONE      = 0
    EXECUTE   = 1
    WRITE     = 2
    READ      = 4
    ALL       = 7

    def __str__(self) -> str:
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    def from_info_sections(cls, *args: str) -> "Permission":
        perm = cls(0)
        for arg in args:
            if "READONLY" in arg: perm |= Permission.READ
            if "DATA" in arg: perm |= Permission.WRITE
            if "CODE" in arg: perm |= Permission.EXECUTE
        return perm

    def from_process_maps(perm_str: str) -> "Permission":
        if perm_str[0] == "r": Permission.READ
        if perm_str[1] == "w": Permission.WRITE
        if perm_str[2] == "x": Permission.EXECUTE
        return perm_str

    def from_monitor_info_mem(cls, perm_str: str) -> "Permission":
        perm = cls(0)
        # perm_str[0] shows if this is a user page, which
        # we don't track
        if perm_str[1] == "r": perm |= Permission.READ
        if perm_str[2] == "w": perm |= Permission.WRITE
        return perm

    @classmethod
    def from_info_mem(cls, perm_str: str) -> "Permission":
        perm = cls(0)
        if "r" in perm_str: perm |= Permission.READ
        if "w" in perm_str: perm |= Permission.WRITE
        if "x" in perm_str: perm |= Permission.EXECUTE
        return perm


