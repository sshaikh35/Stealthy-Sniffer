import pandas as pd
import matplotlib.pyplot as plt

# Load CSV
df = pd.read_csv("captured_traffic.csv")

# Count encryption types
enc_counts = df["Encryption"].value_counts()

# Count suspicious alerts
suspicious_counts = df["Suspicious"].value_counts()

print("\n=== Traffic Summary ===")
print("Total Packets:", len(df))
print("\nEncryption Types:\n", enc_counts)
print("\nSuspicious Events:\n", suspicious_counts)

# Plot encryption stats
plt.figure(figsize=(6,4))
enc_counts.plot(kind="bar", color=["red","green","gray"])
plt.title("Encryption vs Plaintext Traffic")
plt.ylabel("Packet Count")
plt.xticks(rotation=30)
plt.tight_layout()
plt.savefig("encryption_stats.png")
plt.show()

# Plot suspicious stats
plt.figure(figsize=(6,4))
suspicious_counts.plot(kind="bar", color="orange")
plt.title("Suspicious Activity Detected")
plt.ylabel("Occurrences")
plt.xticks(rotation=30)
plt.tight_layout()
plt.savefig("suspicious_stats.png")
plt.show()
