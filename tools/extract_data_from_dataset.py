import pandas as pd

df = pd.read_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-CSE-CIC-IDS2018-v2.csv", nrows= 5_000_000)
# shape = (18893708, 45)

sample = df.sample(n=10, replace=False)
sample.to_csv("C:/Users/Daniel/PycharmProjects/Final_Proj_Anoseek/datasets/NF-CSE-CIC-IDS2018-v2_10_sample.csv", index=False)

print(sample.shape)