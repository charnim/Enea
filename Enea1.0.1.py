import sys
from gittest import VirusTotal, SpreadSheets
import tqdm
import time
from colorama import Fore, init
import shelve

init()

print(Fore.LIGHTCYAN_EX, end='')

# Style.RESET_ALL

if '-h' in sys.argv:

    print("""
HashSum is an automatic hash checker.

It reads a csv file and uploads every hash found in it.

Flags:

Must: 

    -f [file.csv] - specify the csv in the local folder or a full path to the csv file.

Optional:

    -r [number of days] - Will rescan results that are older than the number of days you specified.
    
        -0 will make scan all files anew
    
    -v is verbose, will print the result for every hash.  
    
""")

try:

    if '-r' in sys.argv:

        try:

            days = int(sys.argv[sys.argv.index('-r')+1])

        except ValueError:

            print('\nYou must specify the number of days')

            sys.exit(0)

    if '-f' in sys.argv:

        # Finds the csv file and loads it.

        try:

            csv_file = sys.argv[sys.argv.index('-f')+1]
            customer_excel = SpreadSheets.Csv(csv_file)
            excel_list = customer_excel.CellsAsListNoNumbers
            excel_list = list(set(excel_list))  # Removes duplicates

        except FileNotFoundError:
            customer_excel = ''
            print('\nCannot find file.\n')
            sys.exit()

        # Checks for key.txt file that supposed to the have api key in it.

        try:
            with open('key.txt', 'r', encoding='UTF-8')as keyfile:
                api_key = keyfile.readline()
                if len(api_key) != 64:
                    print('The Key is corrupt, please check the key.txt file')

        except FileNotFoundError:
                print('\nCould not find/open the file in destination, please make sure it exist and is not open at the moment.\n')
                input()
                sys.exit()

        rescanned_list = []

        observable_list = [excel_list, rescanned_list]

        # This part will check for known hashes in database

        with shelve.open('HashSum') as Database:

            if '-r' in sys.argv:

                for hash_ in excel_list:

                    if Database.get(hash_, default=False):

                        if Database[hash_].AgeInSeconds > 86400*days:

                            del Database[hash_]

            known_hashes = 0

            for hash_ in excel_list:

                if Database.get(hash_, default=False):

                    known_hashes += 1

                    if Database[hash_].Positives > 0:

                                    print('\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTCYAN_EX +
                                          ' has {0:2}/{1:2} positives and is tagged as: '.format(Database[hash_].Positives, Database[hash_].Total))

                                    engineCount = 1

                                    print(Fore.LIGHTCYAN_EX, end='')

                                    # Iterates through vendors who have positive and print them.

                                    for vendor in Database[hash_].Scans:

                                        if Database[hash_].Scans[vendor]['detected'] is True:
                                            print('\n\n', str(engineCount) + ')', Fore.LIGHTRED_EX + Database[hash_].Scans[vendor]['result'] + Fore.LIGHTCYAN_EX + "(" + vendor + ")", end=' ')
                                            engineCount += 1

                    if '-v' in sys.argv:

                        if Database[hash_].Positives == 0:

                            print(Fore.LIGHTGREEN_EX + '\n\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTGREEN_EX +
                                  ' has {0:2}/{1:2} and considered CLEAN\n'.format(Database[hash_].Positives, Database[hash_].Total)+Fore.LIGHTCYAN_EX)

                    excel_list.remove(hash_)

        print('\n\nThere are '+Fore.LIGHTGREEN_EX+str(known_hashes)+Fore.LIGHTCYAN_EX+' known hashes, beginning to query virus total:\n')

        for hash_list in observable_list:

            pbar = tqdm.tqdm(hash_list, leave=False, unit_scale=True)

            # main bar.

            with shelve.open('HashSum') as Database:

                for hash_ in pbar:

                    pbar.set_description("Processing %s" % str(' '+hash_)[:100]+'...')

                    # Var query is from database if found, else request virus total and wait 15 seconds.

                    if Database.get(hash_, default=False):

                        query = Database[hash_]

                    else:

                        query = VirusTotal.VirusTotalHash(resource=hash_, api_key=api_key)

                        # Inner bar

                        for i in tqdm.tqdm(range(100)):
                            time.sleep(0.15)

                    # Will print results if there are positives.

                    if query.ResponseCode == 1:

                        # Will renew all requests

                        if '-r' in sys.argv:

                            if query.AgeInSeconds > 86400*days:

                                query = VirusTotal.VirusTotalHashRescan(resource=hash_, api_key=api_key)

                                for i in tqdm.tqdm(range(100)):
                                    time.sleep(0.15)

                                rescanned_list.append(hash_)

                                try:

                                    del Database[hash_]

                                except KeyError:

                                    pass

                            else:

                                query.compressor()

                                Database[hash_] = query

                                if query.Positives > 0:

                                    print('\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTCYAN_EX +
                                          ' has {0:2}/{1:2} positives and is tagged as: '.format(query.Positives, query.Total))

                                    engineCount = 1

                                    print(Fore.LIGHTCYAN_EX, end='')

                                    # Iterates through vendors who have positive and print them.

                                    for vendor in query.Scans:

                                        if query.Scans[vendor]['detected'] is True:
                                            print('\n\n', str(engineCount) + ')', Fore.LIGHTRED_EX + query.Scans[vendor]['result'] + Fore.LIGHTCYAN_EX + "(" + vendor + ")", end=' ')
                                            engineCount += 1

                                    print('\n')

                            if '-v' in sys.argv:

                                if query.Positives == 0:

                                    print(Fore.LIGHTGREEN_EX + '\n\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTGREEN_EX + ' has {0:2}/{1:2} and considered CLEAN\n'.format(Database[hash_].Positives, Database[hash_].Total)+Fore.LIGHTCYAN_EX)

                        else:

                            query.compressor()

                            Database[hash_] = query

                            if query.Positives > 0:

                                print('\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTCYAN_EX +
                                      ' has {0:2}/{1:2} positives and is tagged as: '.format(query.Positives, query.Total))

                                engineCount = 1

                                # Iterates through vendors who have positive and print them.

                                for vendor in query.Scans:

                                    if query.Scans[vendor]['detected'] is True:
                                        print('\n\n', str(engineCount) + ')', Fore.LIGHTRED_EX + query.Scans[vendor]['result'] + Fore.LIGHTCYAN_EX + "(" + vendor + ")", end=' ')
                                        engineCount += 1

                                print('\n')

                            if '-v' in sys.argv:

                                if query.Positives == 0:

                                    print(Fore.LIGHTGREEN_EX + '\n\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTGREEN_EX + ' has {0:2}/{1:2} and considered CLEAN\n'.format(Database[hash_].Positives, Database[hash_].Total)+Fore.LIGHTCYAN_EX)

                    else:

                            if '-v' in sys.argv:

                                print(Fore.LIGHTMAGENTA_EX + '\n\n\nNumber ', excel_list.index(hash_)+1, 'in file', Fore.LIGHTYELLOW_EX+hash_+Fore.LIGHTMAGENTA_EX + ' is UNKNOWN\n'+Fore.LIGHTCYAN_EX)

except KeyboardInterrupt:
    sys.exit(0)
