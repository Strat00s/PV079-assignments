#Order the data and save it, 100 shortest, 100 longest and show average

raw_data = list()
with open("../zadani/492875_data.csv", "r") as f:
    for line in f.readlines():
        data = line.split(",")
        raw_data.append([int(data[0]), int(data[1]), int(data[2])])
    
raw_data.sort(key=lambda x: x[0])

with open("492875_data_ordered.csv", "w") as f:
    for item in raw_data:
        f.write(f"{item[0]},{item[1]},{item[2]}\n")

with open("492875_data_least100.csv", "w") as f:
    for i in range(0, 100):
        f.write(f"{raw_data[i][0]},{raw_data[i][1]},{raw_data[i][2]}\n")

with open("492875_data_most100.csv", "w") as f:
    for i in range(len(raw_data) - 100, len(raw_data)):
        f.write(f"{raw_data[i][0]},{raw_data[i][1]},{raw_data[i][2]}\n")

acc = 0
for item in raw_data:
    acc += item[0]

print(f"Average time: {acc / len(raw_data)}")
