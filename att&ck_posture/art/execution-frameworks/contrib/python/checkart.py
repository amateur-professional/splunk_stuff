# Imports runner.py, sets variables and executes scripts

import runner

def main():

    # Instantiate the AtomicRunner class instance.
    techniques = runner.AtomicRunner()

    techniques.execute("T1033", position=0, parameters={"computer_name": "localhost"})
    techniques.execute("T1089", position=0, parameters={"computer_name": "localhost"})
    techniques.execute("T1086", position=0, parameters={"computer_name": "localhost"})
    techniques.execute("T1030", position=0,)
    techniques.execute("T1046", position=0,)

if __name__ == "__main__":
    main()

