import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.app.db.database import init_db, verify_chain_detailed, verify_chain_incremental, reset_chain_checkpoint

init_db()
print("Comparing full chain verification vs incremental verification...")
reset_chain_checkpoint()

t0 = time.perf_counter()
res_full = verify_chain_detailed()
t_full = (time.perf_counter() - t0) * 1000

t0 = time.perf_counter()
res_inc1 = verify_chain_incremental()
t_inc1 = (time.perf_counter() - t0) * 1000

t0 = time.perf_counter()
res_inc2 = verify_chain_incremental()
t_inc2 = (time.perf_counter() - t0) * 1000

print(f"Full chain scan: {t_full:.3f} ms (events verified: {res_full['events_verified']})")
print(f"Incremental (initial sync): {t_inc1:.3f} ms (events verified: {res_inc1['events_verified']})")
print(f"Incremental (steady state / new link): {t_inc2:.3f} ms (events verified: {res_inc2['events_verified']})")
