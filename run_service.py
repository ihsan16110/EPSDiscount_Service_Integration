#!/usr/bin/env python
import uvicorn
import sys

if __name__ == "__main__":
    uvicorn.run(
        "eps_discount_integration:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        reload=False
    )
