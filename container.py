from pefile import PE


class Container:
    @property
    def image_base(self) -> int:
        raise NotImplementedError()

    @property
    def image_size(self) -> int:
        raise NotImplementedError()

    def in_range(self, va: int):
        return va >= self.image_base and va < self.image_base + self.image_size

    def get_data(self, va: int, size: int) -> bytes:
        raise NotImplementedError()


class RawContainer(Container):
    def __init__(self, data: bytes, image_base=0):
        self.data = data
        self._image_base = image_base
        self._image_size = len(data)

    @property
    def image_base(self) -> int:
        return self._image_base

    @property
    def image_size(self) -> int:
        return self._image_size

    def get_data(self, va: int, size: int) -> bytes:
        assert self.in_range(va)
        rva = va - self.image_base
        return self.data[rva : rva + size]


class PEContainer(Container):
    def __init__(self, pe: str | PE) -> None:
        if isinstance(pe, str):
            pe = PE(pe)
        self.pe = pe
        self._image_base = pe.OPTIONAL_HEADER.ImageBase  # pyright: ignore
        self._image_size = pe.OPTIONAL_HEADER.SizeOfImage  # pyright: ignore

    @property
    def image_base(self) -> int:
        return self._image_base

    @property
    def image_size(self) -> int:
        return self._image_size

    def get_data(self, va: int, size: int) -> bytes:
        assert self.in_range(va)
        rva = va - self.image_base
        return self.pe.get_data(rva, size)
