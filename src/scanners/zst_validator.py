import zstandard as zstd
import os
from ..utils.config_loader import config_manager

class ZstdValidator:
    def validate(self, file_path):
        try:
            dctx = zstd.ZstdDecompressor()
            # Use limits from YAML config
            uncompressed_mb = config_manager.get('limits.max_zst_decompression_mb', 100)
            max_uncompressed_limit = uncompressed_mb * 1024 * 1024 
            max_ratio = config_manager.get('limits.max_compression_ratio', 100)
            
            compressed_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as ifh:
                try:
                    with dctx.stream_reader(ifh) as reader:
                        total_read = 0
                        while True:
                            chunk = reader.read(65536)
                            if not chunk:
                                break
                            total_read += len(chunk)
                            
                            # Check 1: Abs limit
                            if total_read > max_uncompressed_limit:
                                return {"passed": False, "reason": "Decompression Bomb: absolute uncompressed size too large."}
                            
                            # Check 2: Ratio limit
                            if compressed_size > 0 and (total_read / compressed_size) > max_ratio:
                                return {"passed": False, "reason": f"Decompression Bomb: suspicious compression ratio (>{max_ratio}x)."}
                except zstd.ZstdError as err:
                    return {"passed": False, "reason": f"Invalid Zstandard format: {err}"}
                    
            return {"passed": True}
        except Exception as e:
            return {"passed": False, "reason": f"ZST decompression error: {str(e)}"}
