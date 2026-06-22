import pandas as pd

df = pd.read_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-CSE-CIC-IDS2018-v2.csv", nrows= 1_000_000)
# shape = (18893708, 45)

#sample = df.sample(n=2_000_000, replace=False)
df.to_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-CSE-CIC-IDS2018-v1M_sample.csv", index=False)

print(df.shape)