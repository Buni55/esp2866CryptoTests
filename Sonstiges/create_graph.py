import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("gcm_v3.csv")

transposed_data = data.set_index('Method').T


plt.figure(figsize=(18, 8))


for column in transposed_data.columns:
    if 'Encrpytion' in column:

        plt.plot(transposed_data.index, transposed_data[column], label=column)
    elif 'Decrpytion' in column:

        plt.plot(transposed_data.index, transposed_data[column], '-.', label=column)

plt.title('Run Times for Random Plaintext and Key')
plt.xlabel('Runs')
plt.ylabel('Time in Microseconds')
plt.xticks(rotation=90)
plt.legend(title='Methods')
plt.grid(True)
print(data.head())
plt.savefig('plot_output.png', format="png", dpi=300)




