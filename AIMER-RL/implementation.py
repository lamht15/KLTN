import os
from tabnanny import check
import gp
import rl
import sys
import json
import requests
import functions as f
import endgameinc as eg
from random import choice
from shutil import copyfile
import data.manipulate as m
from datetime import datetime
from time import time, sleep, strftime, gmtime
from subprocess import call, check_output, CalledProcessError, Popen, PIPE, STDOUT, run

# Paths
mod_path = "samples/mod/"
fail_path = "samples/unsuccessful/"
evasion_path = "samples/successful/"
detected_path = "samples/successful/detected/"
unzipped_path = "samples/malware/"
evaluation_path = "samples/evaluate_set/"
malware_original_name = None
# Default fields for database
fields = ['Original_File', 'OF_Detections', 'Manipulated_File', 'MF_Detections', 'Perturbations',
          'Perturbations_Injected',
          'Full_Detections_Report', 'Full_Analysis_Report', 'Mod_File_Hash', 'Original_File_Hash', 'Date_Reported']


#				HANDLE INPUT PARAMETERS


def handling_input(args):
    '''
        Handle input entered on terminal when calling AXMED
    '''
    n = 0
    files_expected = detection_threshold = -1
    rounds = files_expected ** 3 if files_expected > 9 else 100
    sample = unzipped_path + choice(os.listdir(unzipped_path))  # random
    if len(args) <= 6:
        print('\nSelect random malware sample: \n{}'.format(sample))
        n = int(args[2])
        files_expected = int(args[4])
    elif len(args) > 6:
        n = int(args[2])
        if args[3] == '-r':
            rounds = int(args[4])
        elif args[3] == '-m':
            files_expected = int(args[4])
            if args[5] == '-r':
                rounds = int(args[6])
            else:
                rounds = files_expected ** 3 if files_expected > 9 else 100
        elif args[7] == '-t':
            detection_threshold = int(args[8])
            rounds = 100
        if len(args) > 8:
            if args[7] == '-m' and not args[5] == '-m':
                files_expected = int(args[8])
                rounds = files_expected ** 3 if files_expected > 9 else 100
            elif args[7] == '-t' and not args[5] == '-t':
                detection_threshold = int(args[8])
                rounds = 100
            else:
                raise ValueError('Argument not accepted: {} {}. Please check usage with -h'. \
                                 format(args[7], int(args[8])))
            if len(args) > 10:
                if args[9] == '-t' and not (args[7] == '-t' or args[7] == '-m' or \
                                            args[5] == '-t' or args[5] == '-m'):
                    detection_threshold = int(args[10])
                    rounds = 100
                else:
                    raise ValueError('Arguments not accepted: {} {}. Please check usage with -h'. \
                                     format(args[9], int(args[10])))

    return sample, n, rounds, files_expected, detection_threshold


#				IMPLEMENTATION AIMED / ARMED FRAMEWORKS


def aimed(bin_bytes, sample, size_population, length_sequence, files_expected, scanner):
    '''
        AIMED: Automatic Intelligent Malware Modifications to Evade Detection
        This function implements GP to find PE adversarial examples.

        Input:
            bin_bytes: binaries from input malware sample
            sample: malware sample in terminal
            size_population: population size for GP (Default: 4)
            length_sequence: length of perturbation sequence
            files_expected: number of malware mutations expected as output
            scanner: commercial AV or malware model classifier
    '''

    # Create a dict with all perturbations
    actions = f.actions_vector(m.ACTION_TABLE.keys())

    # Inject children sequences to S to create four S'
    mutation = {}
    mutation['Malware_Bytes'], mutation['Malware_Sample'], mutation['Actions'], \
    mutation['Files_Expected'], mutation['hash_sample'], mutation['Scanner'] = \
        bin_bytes, sample, actions, files_expected, f.hash_files(sample), scanner

    # Call evolution algorithm to find successfull mutations
    print('\n### AIMED: Automatic Intelligent Malware Modifications to Evade Detection ###')
    population = gp.Population(size=size_population, length_sequence=length_sequence, show_sequences=True)
    return population.generation(mutation=mutation)


def armed(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner):
    '''
        ARMED: Automatic Random Malware Modifications to Evade Detection
        This function injects n random perturbations to input PE malware
        in order to find adversarial examples.

        Input:
            bin_bytes: binaries from input malware sample
            sample: malware sample in terminal
            n: number of perturbations to inject
            rounds: number of rounds to run when searching for evasions
            files_expected: number of malware mutations expected as output
            detection_threshold: run until number of detections is below threshold (only for VirusTotal)
            scanner: commercial AV or malware model classifier
    '''
    # Decide whether to use remote (VirusTotal) or local detection & remote or local sandbox
    useVT = False
    useHA = False

    # Iterate to generate -m mutations for all perturbations on the loop 
    start = time()
    max_number_perts = n
    while n <= max_number_perts:
        new_samples = 0
        new_corrupt_samples = 0
        for r in range(rounds):

            # Create a dict with all perturbations & choose random actions 
            actions = f.actions_vector(m.ACTION_TABLE.keys())
            chosen_actions = f.create_random_actions(len(actions), n)

            # Call a recursive function to inject n perturbations on a given sample
            print('\n### ARMED: Automatic Random Malware Modifications to Evade Detection ###\n')
            print('# Manipulation Box # Round {} of {} #\n'.format(r + 1, rounds))
            perturbs = n - 1
            start_pert = time()
            mod_sample = f.rec_mod_files(bin_bytes, actions, chosen_actions, perturbs, n)
            print('Time injecting perturbations: {} s'.format(round(time() - start_pert, 2)))

            # Send the modified sample to sandbox to check functionality (not corrupt)
            print('\n# Sandbox (Oracle) # Round {} of {} #'.format(r + 1, rounds))

            # Check if use remote or local sandbox
            if useHA:
                json_send_HA = f.send_HA(mod_sample, 120)
            else:
                json_send = f.send_local_sandbox(mod_sample)

                # Calculate hashes from original and modified sample
            hash_sample = f.hash_files(sample)
            mod_sample_hash = f.hash_files(mod_sample)

            # Get VT detections for original sample to use as benchmark
            if useVT:
                sample_report = f.get_report_VT(hash_sample, rescan=False)
            else:
                sample_report = {'positives': 49, 'total': 66}  # Debug mode (without VT/offline)

            # Collect info to writeCSV function 
            CSV = f.collect_info_CSV(sample, sample_report, n - 1, chosen_actions, mod_sample_hash, hash_sample)

            # Malware analysis & malware detection stages
            funcional = False
            funcional, url_sandbox = malware_analysis(mod_sample, json_send, useVT, CSV)

            # Check if use remote or local detection along with functionality 
            if useVT and funcional:
                new_samples += 1
                CSV['Full_Analysis_Report'] = url_sandbox
                vt_positives = malware_detection_VT(sample_report, CSV)
                if vt_positives < detection_threshold:
                    break

            elif not useVT and funcional:
                print('# Malware Classifier # Round {} # Perturbation {} of {} #\n'.format(r + 1,
                                                                                           int(CSV['Perturbations']),
                                                                                           n))
                # Check if mutation is detected
                start = time()
                mutation = CSV['Perturbations'] + '_m.exe'
                print('Running detection for:', mutation)
                detected = malware_detection(mutation, scanner)
                new_samples += save_file_database(detected, mutation, url_sandbox, CSV, scanner)

            elif not funcional:
                new_corrupt_samples += 1

            if r == rounds - 1:
                print('\n## Summary ##')

            if new_samples == files_expected:
                break

        print('Evasive mutations found: {}'.format(new_samples))
        print('Corrupt mutations found: {}'.format(new_corrupt_samples))
        n += 1

    return new_samples, new_corrupt_samples


def armed2(bin_bytes, sample, n, rounds, files_expected, scanner):
    '''
        ARMED-II: Automatic Random Malware Modifications to Evade Detection -- Incremental Iterations
        This function injects random perturbations sequentially to input PE malware
        in order to find adversarial examples. After each injection, the malware
        mutation will be tested for functionality and evasion.

        Input:
            bin_bytes: binaries from input malware sample
            sample: malware sample in terminal
            n: number of perturbations to inject
            rounds: number of rounds to run when searching for evasions
            files_expected: number of malware mutations expected as output
            scanner: commercial AV or malware model classifier
    '''
    # Decide whether to use remote (VirusTotal) or local detection
    useVT = False

    # Create a dict with all perturbations
    actions = f.actions_vector(m.ACTION_TABLE.keys())

    # Get VT detections for original sample to use as benchmark
    hash_sample = f.hash_files(sample)
    if useVT:
        sample_report = f.get_report_VT(hash_sample, rescan=False)
    else:
        sample_report = {'positives': 49, 'total': 66}  # Debug mode (without VT/offline)

    # Inject perturbations and check for detection
    chosen_actions = [None] * n
    new_mutations = 0
    for x in range(n):

        for r in range(rounds):

            # Create random action and add it to sequence
            random_actions = f.create_random_actions(len(actions), x + 1)
            chosen_actions[x] = random_actions[0]

            print('\n### ARMED-II: Automatic Random Malware Modifications to Evade Detection ###\n')
            print('# Manipulation Box # Round {} # Perturbation {} of {} #\n'.format(r + 1, x + 1, n))

            # Call a recursive function to inject x perturbations on a given sample (Print = Perturbation: x+1)
            mod_sample = f.rec_mod_files(bin_bytes, actions, chosen_actions, x, x + 1)

            print('\n# Sandbox (Oracle) # Round {} # Perturbation {} of {} #'.format(r + 1, x + 1, n))

            # Send the modified sample to sandbox to check functionality (not corrupt)
            json_send = f.send_local_sandbox(mod_sample)

            # Calculate hashes from original and modified sample
            mod_sample_hash = f.hash_files(mod_sample)

            # Collect info to writeCSV function
            CSV = f.collect_info_CSV(sample, sample_report, x, chosen_actions, mod_sample_hash, hash_sample)

            # Malware analysis & malware detection stages
            useVT = False
            funcional = False
            funcional, url_sandbox = malware_analysis(mod_sample, json_send, useVT, CSV)

            # Increase number of mutations to match -m given based on local checks
            if funcional:
                print('# Malware Classifier # Round {} # Perturbation {} of {} #\n'.format(r + 1,
                                                                                           int(CSV['Perturbations']),
                                                                                           n))
                # Check if mutations is detected
                start = time()
                mutation = CSV['Perturbations'] + '_m.exe'
                print('Running detection for:', mutation)
                detected = malware_detection(mutation, scanner)
                new_mutations += save_file_database(detected, mutation, url_sandbox, CSV, scanner)

            if new_mutations == files_expected:
                break

    # Show time
    print('Evasive mutations found: {}'.format(new_mutations))

def get_original_name(name):
    return name

def aimed_rl(directory_agent=None, train=True, evaluate=False):
    """
        AIMED-RL: Automatic Intelligent Malware Modifications using Reinforcement Learning
        base_directory: Training Directory of an existing agent (evaluation only)
        train: Creates and trains a new agent
        evaluate:Evaluates an existing agent
        (either train or eval or both must be true)
    """
    assert train or evaluate, "AIMED-RL must either train or evaluate or both"
    training_report = None
    # Train:
    if train:
        assert directory_agent is None, "AIMED-Rl training does not require a directory"
        print("AIMED-RL TRAINING Started!")
        training_report, directory_agent = rl.train_and_save_agent(malware_detection=malware_detection,
                                                                     malware_analysis=check_functionality)

    # Evaluate - MalConv, GradientBoosting, NonNegMalConv
    if evaluate:
        def change_permissions(path):
            try:
                os.chmod(path, 0o777)  # Full permissions for the owner, group, and others
            except Exception as e:
                print(f"Error changing permissions for {path}: {e}")
        #link = "C:/Users/thanh/OneDrive/Máy tính/Dataset/Dataset/Virus/Virus train/Zbot/AIMER-RL/samples/Zbot_mutation/fc43273973bc12da70d623221b8ccd4c50302402.exe"
        # mutation_link = "C:\\Users\\thanh\\Downloads\\KLTN\\AIMER-RL\\samples\\Full_train\\full_train_1"
        mutation_link = "C:\\Users\\thanh\\Downloads\\KLTN\\AIMER-RL\\samples\\Danh gia mo hinh 2 TH\\Func"
        change_permissions(mutation_link)
        # malware_detection(mutation_link, "MalConv", 0.9)
        # detection_name = ["MalConv", "GradientBoosting", "NonNegMalConv"]
        count_pass = 0
        count = 0
        for filename in os.listdir(mutation_link):
            file_path = os.path.join(mutation_link, filename)
            check, score = malware_detection(file_path, "GradientBoosting", 0.9)
            if not check: 
                count_pass += 1
            print("==================================")
            print(f"Check: {check}, Score: {score}")
            print("==================================")
            count +=1
        print(f"Total 'Sample not detected': {count_pass} --- ", count)
        #=============================================================================================================================================================
        # directory_agent = "C:/Users/thanh/Downloads/KLTN/AIMER-RL/db/rl/2024-06-20-21-14"
        # print(directory_agent)
        # assert directory_agent is not None, "AIMED-RL evaluation needs a base directory"
        # if not directory_agent[-1] == "/":
        #     directory_agent += "/"

        # print("Starting evaluation for " + directory_agent)

        # assert os.path.exists(directory_agent), "Agent directory not found"

        # files = os.listdir(directory_agent)
        # if training_report is None:
        #     for file in files:
        #         if "training_report" in file:
        #             training_report = file
        #             break
        # assert training_report is not None, "Training information not found"

        # print("AIMED-RL EVALUATION Started!")
        # rl.load_and_evaluate_agent(directory_agent=directory_agent,
        #                            agent_information=directory_agent + '/' + training_report,
        #                            evaluation_set_directory=evaluation_path,
        #                            malware_detection=malware_detection,
        #                            malware_analysis=check_functionality)
      

#				COMPARING ARMED vs AIMED 


def comparing(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner):
    '''
        This function compares ARMED and AIMED to assess random vs. evolutionary performance
        finding adversarial examples. The results will be stored on compare.csv
    '''

    # Run ARMED
    start_Total = time()
    start_ARMED = time()
    _, ARMED_corrupt_samples = armed(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner)
    time_ARMED = f.time_me(start_ARMED)

    # Run AIMED
    size_population = 4
    start_AIMED = time()
    AIMED_new_evasions, AIMED_corrupt_files = aimed(bin_bytes, sample, size_population, n, files_expected, scanner)
    time_AIMED = f.time_me(start_AIMED)

    # Update CSV with comparison data
    Compare_CSV = {}
    fields_compare = ['Sample', 'Perturbations', 'Module 1', 'Time M1', 'Files M1', 'Corr M1', 'Module 2', 'Time M2',
                      'Files M2', 'Corr M2', 'Total Time']
    Compare_CSV['Sample'], Compare_CSV['Perturbations'], Compare_CSV['Module 1'], Compare_CSV['Time M1'], Compare_CSV[
        'Files M1'], \
    Compare_CSV['Corr M1'], Compare_CSV['Module 2'], Compare_CSV['Time M2'], Compare_CSV['Files M2'], Compare_CSV[
        'Corr M2'], Compare_CSV['Total Time'] = \
        sample, n, 'ARMED', time_ARMED, files_expected, ARMED_corrupt_samples, 'AIMED', time_AIMED, AIMED_new_evasions, AIMED_corrupt_files, strftime(
            '%H:%M:%S', gmtime(time() - start_Total))
    f.write_dict_CSV('db/compare.csv', Compare_CSV, fields_compare)

    # Update short version CSV with time averages to use as input in LaTeX
    f.comparing_AXMED()


#				SAVE NEW MUTATIONS AND UPDATE DATABASE FOR ALL MODULES (ARMED / ARMED-II / AIMED)


def save_file_database(detected, mutation, url_sandbox, CSV, scanner):
    '''
        Structure manipulation and logic to update DB

        Input:
            detected: Boolean value whether malware mutation is detected
            mutation: Name of malware with path
            url_sandbox: URL to functionality report (default: Cuckoo sandbox)
            CSV: Structure to save in DB
            scanner: malware classifier
    '''

    if not detected:

        # Copy successful sample into evasion path
        now = datetime.now()
        name_file = str(now.year) + str(now.month) + str(now.day) + \
                    str(now.hour) + str(now.minute) + str(now.second)
        copyfile(mod_path + mutation, evasion_path + \
                 CSV['Perturbations'] + 'm_' + name_file + '.exe')

        # Update CSV with successful mutation
        CSV['Manipulated_File'], CSV['Full_Analysis_Report'], \
        CSV['MF_Detections'], CSV['Full_Detections_Report'], CSV['Date_Reported'] = \
            evasion_path + CSV['Perturbations'] + 'm_' + name_file + '.exe', \
            url_sandbox, 'Evasion', scanner, str(datetime.now())
        f.write_dict_CSV('db/evasion.csv', CSV, fields)

        print('Results: Evasion found for {}!\n'.format(scanner))
        # print('Evasive sequence: {}'.format(chosen_actions[:int(CSV['Perturbations'])]))

        return 1

    else:

        # Copy valid sample but detected into detected_path
        now = datetime.now()
        name_file = str(now.year) + str(now.month) + str(now.day) + \
                    str(now.hour) + str(now.minute) + str(now.second)
        copyfile(mod_path + mutation, detected_path + \
                 CSV['Perturbations'] + 'm_' + name_file + scanner + '.exe')

        # Update CSV with valid mutation but detected by scanner
        CSV['Manipulated_File'], CSV['Full_Analysis_Report'], \
        CSV['MF_Detections'], CSV['Full_Detections_Report'], CSV['Date_Reported'] = \
            detected_path + CSV['Perturbations'] + 'm_' + name_file + scanner + '.exe', \
            url_sandbox, 'Detected', scanner, str(datetime.now())
        f.write_dict_CSV('db/detected.csv', CSV, fields)

        return 0


#				MALWARE ANALYSIS STAGE (LOCAL)


def malware_analysis(mod_sample, json_send, useVT, CSV):
    '''
        Analyze malware with sandbox Cuckoo

        Input:
            mod_sample: Compiled version of modified malware mutation
            json_send: JSON status after sending mutation to local sandbox for analysis
            useVT: Boolean value indicating whether VirusTotal is used or detection will be performed locally
            CSV: Data structure with information to save on DB
    '''

    loops = 0
    start = time()
    functionality = True

    # Show report from analisys sandbox: report URL + Job ID
    url_sample = 'http://localhost:8000/analysis/' + str(json_send['task_id']) + '/summary'
    print('\nFull analysis report: {}\n\nStatus:'.format(url_sample))

    # Using sleep in loop to space requests to sandbox may improve results
    firstPrintR, firstPrintW, firstPrintRep = True, True, True
    while True:
        try:
            v = f.get_summary_local_sandbox(json_send['task_id'], 'view')
            view_status = v['task']['status']
            if view_status == 'completed' and firstPrintRep:
                print('Analysis finished. Generating report..')
                firstPrintRep = False
            elif view_status == 'pending' and firstPrintW:
                print('Waiting in queue to be analyzed..')
                firstPrintW = False
            elif view_status == 'running' and firstPrintR:
                print('Analysis in progress..')
                firstPrintR = False
            elif view_status == 'reported':
                print('Report finished.')
                break
            sleep(0.2)

        except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
            print('Connection issues or API not available:\n{}'.format(e))

            # Check the likelihood that malware runs based on report
    err = 'CuckooPackageError: Unable to execute the initial process, analysis aborted.\n'
    r = f.get_summary_local_sandbox(json_send['task_id'], 'report')
    report = r['debug']['cuckoo']
    duration = r['info']['duration']
    if err not in report and duration >= 15:
        functionality = True
        print('\nResults: WORKING')

        # Show analysis time in hh:mh:ss
        f.time_me(start)

        # Send to VT for detections (activate if local detection is not used)
        if useVT:
            print('Sending to VirusTotal!')
            json_send_VT = f.send_VT(mod_sample)

    elif err not in report and duration < 15:
        print('\nResults: It could not be determined (score = {} – duration = {})'.format(r['info']['score'], duration))

        # Show analysis time in hh:mh:ss
        f.time_me(start)

    elif err in report:
        print('\nResults: Mutation is corrupt')

        # Copy sample into failed path & tag with letter F
        now = datetime.now()
        name_file = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute)
        copyfile(mod_path + CSV['Perturbations'] + '_m.exe', \
                 fail_path + CSV['Perturbations'] + 'F_' + name_file + '.exe')

        # Update database with basic sample's info
        CSV['Manipulated_File'], CSV['Full_Analysis_Report'], CSV['Date_Reported'] \
            = fail_path + CSV['Perturbations'] + 'F_' + name_file + '.exe', url_sample, str(datetime.now())
        f.write_dict_CSV('db/corrupted.csv', CSV, fields)

        # Show analysis time in hh:mh:ss
        f.time_me(start)

    return functionality, url_sample


#				MALWARE ANALYSIS STAGE (REMOTE)


def malware_analysis_HA(mod_sample, json_send_HA, CSV):
    '''
        Analyze malware using remote service Hybrid Analysis
    '''

    loops = 0
    start = time()
    functionality = True

    # Wait a few minutes if server did not accept further submissions
    while json_send_HA == 429:
        print('Submission quota limit has been exceeded. Retry in 5 minutes.')
        sleep(301)

    # Retrieve report from Hybrid Analisys sandbox: report URL + Hash + Job ID
    url_sample = 'https://www.reverse.it/sample/' + json_send_HA['sha256'] + '/' + json_send_HA['job_id']
    print('\nFull report: {}\n\nStatus:'.format(url_sample))

    # Use loops and sleep to keep requests low and avoid API banned by HA (Limit: 5/m)
    limit = 30
    while loops < limit:
        try:
            # Server could return 403
            if f.url_ok(url_sample) == 200 or f.url_ok(url_sample) == 403:
                report_HA = f.get_summary_HA(json_send_HA['sha256'])
                if report_HA['state'] == 'ERROR':
                    print('The sandbox environment returned {}.'.format(report_HA['error_type']))
                    break
                elif report_HA['state'] == 'IN_QUEUE':
                    print('Waiting in queue to be analyzed. Next update in 60 s')
                elif report_HA['state'] == 'IN_PROGRESS':
                    print('Analysis in progress..')
                elif report_HA['state'] == 'SUCCESS':
                    print('Analysis finished.')
                    break
                    sleep(60)
            else:
                print('Website not reachable. Next update in 30 s')
                sleep(30)

            if loops == limit - 1:
                print('ARMED exited because the limit of {} minutes has been reached.\n'.format(limit))
                quit()

            loops += 1

        except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
            print('Connection issues or API requests reached:\n{}'.format(e))

            # Check the likelihood that malware runs based on report
    if report_HA['domains'] or report_HA['compromised_hosts']:
        functionality = True
        print('\nResults: WORKING')
        print('Malware connects to domains or contacts hosts.')

        # Show analysis time in hh:mh:ss
        f.time_me(start)

        # Send to VT to check detections
        print('Sent to VirusTotal!')
        json_send_VT = f.send_VT(mod_sample)

    else:
        if report_HA['state'] != 'ERROR':
            print('\nResults: Most likely not working')
            print('Check if manipulated sample runs before scanning.')
            print('Malware does not connect to domains or contacts hosts.')

            # Copy sample into failed path & tag with F
            now = datetime.now()
            name_file = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute)
            copyfile(mod_path + CSV['Perturbations'] + '_m.exe', \
                     fail_path + CSV['Perturbations'] + 'F_' + name_file + '.exe')

            # Update database with basic sample's info
            CSV['Manipulated_File'], CSV['Full_Analysis_Report'] \
                = fail_path + CSV['Perturbations'] + 'F_' + name_file + '.exe', url_sample
            f.write_dict_CSV('db/fail_database.csv', CSV, fields)

            # Show analysis time in hh:mh:ss
            f.time_me(start)

    return functionality, url_sample


#				MALWARE DETECTION STAGE (VIRUSTOTAL & METADEFENDER)


def malware_detection_VT(sample_report, CSV):
    '''
        Detecting malware samples using VirusTotal (remote)

        Input:
            sample_report: the number of VT detections to use as benchmark
    '''

    loops = 0
    limit = 20
    start = time()

    # Comparing detections of both samples 
    print('\n# Malware Detection Stage #')
    print('\nOriginal sample:')
    print('Detected by {} out of {} engines \n'.format(sample_report['positives'],
                                                       sample_report[
                                                           'total']))  # , (sample_report['positives']/sample_report['total'])*100))
    print(sample_report['permalink'])
    print('\nStatus:')

    # Use loops and sleep to keep requests lows and avoid API banned by VT (Limit: 100)
    while loops < limit:
        try:
            # Getting report of sample submitted via VT API - Rescan: False
            report = f.get_report_VT(CSV['Mod_File_Hash'], False)

            # Check the status of sample & report
            if report['response_code'] == -2:
                print('The sample is queued for analysis. Next update in 60 s')
                sleep(60)

            elif report['response_code'] == 1:
                print('\nResults: New sample found')
                print('\nDetected by {} out of {} engines \n'.format(report['positives'],  # ({:.2f}%)
                                                                     report[
                                                                         'total']))  # , (report['positives']/report['total'])*100))

                # Print only engines detecting new sample
                av_detect = {key: val for key, val in report['scans'].items() if val['detected'] == 1}
                print(list(av_detect.keys()))

                # Provide link to sample detections report 
                print('\n{}'.format(report['permalink']))

                # Calculate evasion rate based on original sample detections and print summary
                print('\n## Summary ##')
                print(
                    '\nEvasion rate: {:.2f}% of previous engines'.format((1 - (report['positives'] / report['total']) /
                                                                          (sample_report['positives'] / sample_report[
                                                                              'total'])) * 100))
                # print('\nEvasion rate: {:.2f}% of engines'.format((sample_report['positives']/
                # sample_report['total']-report['positives']/report['total'])*100))

                # Show detection time in hh:mm:ss
                f.time_me(start)

                # Copy successful sample into evasion path  
                now = datetime.now()
                name_file = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute) + str(
                    now.second)
                copyfile(mod_path + CSV['Perturbations'] + '_m.exe', \
                         evasion_path + CSV['Perturbations'] + 'm_' + name_file + '.exe')

                # Update database with sample's info 
                CSV['Manipulated_File'], CSV['MF_Detections'], CSV['Full_Detections_Report'], \
                CSV['Date_Reported'] = evasion_path + CSV['Perturbations'] + 'm_' + \
                                       name_file + '.exe', str(report['positives']) + '/' + str(report['total']), \
                                       str(report['permalink']), str(report['scan_date'])
                f.write_dict_CSV('db/database.csv', CSV, fields)

                return report['positives']

            else:  # 'response_code' == 0:
                print("Sample is not present in VirusTotal's dataset")
                sleep(60)
            loops += 1

        except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
            print('Connection issues or API requests threshold reached: {}'.format(e))


def malware_detection_MD(sample):
    '''
        Detecting malware samples using MetaDefender (remote)
    '''

    import functions as f
    from time import time, sleep
    start = time()
    res = f.send_MD(sample)
    print('Mutation submitted \nId:', res['data_id'])
    ret = f.get_report_MD(res['data_id'])
    try:
        while ret['original_file']['progress_percentage'] < 100:
            sleep(10)
            ret = f.get_report_MD(res['data_id'])
            print('Progress:', ret['original_file']['progress_percentage'])

        print('Detections: {} out of {}'.format(ret['scan_results']
                                                ['total_detected_avs'], ret['scan_results']['total_avs']))
        print('Time elapsed: {:.2f} s'.format(time() - start))
    except:
        print('Error handling')


#				MALWARE DETECTION STAGE (LOCAL)

def malware_predetect(bin_bytes, snapshot, threshold=0.999):
    if snapshot == 'GradientBoosting':
        av_model = f.load_av('data/lgbm_ember.pkl')
        # bin_bytes = f.readfile(mod_path + mutation)
        score = f.get_score_local(bin_bytes, av_model)
        if score > threshold:  # As per paper
            print("Threshold: ",threshold)
            print("Score: ", score)
            print('\nGB: Malware detected.\n')
            return True, score
        else:
            print("Threshold: ",threshold)
            print("Score: ", score)
            print('\nGB: Sample not detected.\n')
            return False, score
    elif snapshot == 'MalConv':
        av_model = eg.load_malconv()
        # bin_bytes = f.readfile(mod_path + mutation)
        score = av_model.predict(bin_bytes)
        
        if score > threshold:
            print("Threshold: ",threshold)
            print("Score: ", score)
            print("\nMalConv: Malware detected.\n")
            return True, score
        else:
            print("Threshold: ",threshold)
            print("Score: ", score)
            print("\nMalConv: Sample not detected.\n")
            return False, score
    elif snapshot == 'NonNegMalConv':
        av_model = eg.load_nonneg_malconv()
        # bin_bytes = f.readfile(mod_path + mutation)
        score = av_model.predict(bin_bytes)
        
        if score > threshold:
            print("\nNonNegMalConv: Malware detected.\n")
            return True, score
        else:
            print("\nNonNegMalConv: Sample not detected.\n")
            return False, score
    

def malware_detection(mutation, snapshot, threshold=0.999):
    '''
        Detecting malware samples using local scanners.
        Use malware classifiers from industry or academia:
        Gradient Boosting [Anderson et al. 2018]: Trained with 100k
        malicious and benign samples and achieves ROC-AUC = 0.993
        Threshold of 0.9 correponds to 1% FPR at 90% TPR
        A functionality (beta)-test has been added that overcomes the
        processing time of Cuckoo by 1/3 reducing from 45 to 15 s.
    '''


    # if not (snapshot == 'GradientBoosting' or snapshot == 'Functionality'):
    #     print('Engines supported: GradientBoosting')
    #     sys.exit()

    # Pre-trained Gradient Boosting Model
    if snapshot == 'GradientBoosting':
        av_model = f.load_av('data/lgbm_ember.pkl')
        # bin_bytes = f.readfile(mod_path + mutation)
        bin_bytes = f.readfile(mutation)
        score = f.get_score_local(bin_bytes, av_model)
        if score > threshold:  # As per paper
            print("Threshold: ",threshold)
            print("Mutation name: ", mutation)
            print("Score: ", score)
            print('\nGB: Malware detected.\n')
            return True, score
        else:
            print("Threshold: ",threshold)
            print("Mutation name: ", mutation)
            print("Score: ", score)
            print('\nGB: Sample not detected.\n')
            return False, score
    elif snapshot == 'MalConv':
        av_model = eg.load_malconv()
        file_name = mod_path + mutation#kphai folder - train
        # file_name = mutation #test
        print("Xử lý mod file", file_name)
        print("====")
        print("====")
        print("====")
        print("====")
        # bin_bytes = f.readfile(mod_path + malware_original_name + "/" + mutation)
        bin_bytes = f.readfile(file_name)
        score = av_model.predict(bin_bytes)
        
        if score > threshold:
            print("Threshold: ",threshold)
            print("Score: ", score)
            print("\nMalConv: Malware detected.\n")
            return True, score
        else:
            print("Threshold: ",threshold)
            print("Score: ", score)
            print("\nMalConv: Sample not detected.\n")
            return False, score
    elif snapshot == 'NonNegMalConv':
        av_model = eg.load_nonneg_malconv()
        # bin_bytes = f.readfile(mod_path + mutation)
        bin_bytes = f.readfile(mutation)
        score = av_model.predict(bin_bytes)
        
        if score > threshold:
            print("Threshold: ",threshold)
            print("Mutation name: ", mutation)
            print("Score: ", score)
            print("\nNonNegMalConv: Malware detected.\n")
            return True, score
        else:
            print("Threshold: ",threshold)
            print("Mutation name: ", mutation)
            print("Score: ", score)
            print("\nNonNegMalConv: Sample not detected.\n")
            return False, score
        

    # print("Checking mutation", mutation)

    # Start & restore the VM (headless = invisible)
    # state = check_output(['VBoxManage', 'showvminfo', vm]).decode('UTF-8')
    # if "powered off" in state or "saved" in state:
    #     call(['VBoxManage', 'snapshot', vm, 'restore', 'Safe3'])
    #     call(['VBoxManage', 'startvm', vm, '--type', 'headless'])
    # elif "paused" in state:
    #     call(['VBoxManage', 'controlvm', vm, 'resume', '--type', 'headless'])

    # try:

    #     # Beta-test to check functionality (Reduces time of Cuckoo by 1/3 but needs further testing)
    #     if snapshot == "Functionality":
    #         status = None
    #         try:
    #             status = check_output(['timeout', '3', 'VBoxManage', 'guestcontrol', vm, '--username', 'haole', '--password',
    #                  'qwerty', 'run', '--exe', path_m + mutation])
    #             print("---------------------------Status")
    #             print(status)
    #             # print(status)
    #         except Exception as err:
    #             print("---------------------------Error")
    #             print(str(err))
    #             if 'returned non-zero exit status 1.' in str(err):
    #                 print('\nMutation corrupt!\n')
    #                 valid = False
    #             else:
    #                 print('\nMutation WORKING!\n')
    #                 valid = True
    #             return valid, 0.5

    # except CalledProcessError as err:
    #     state = err

    # # Terminate the running process
    # if snapshot != "Functionality":
    #     s.kill()

    # # Pause the VM – Use pause only if power-off is on main()
    # # call(['VBoxManage', 'controlvm', vm, 'pause', '--type', 'headless'])

    # # Power off the VM
    # call(['VBoxManage', 'controlvm', vm, 'poweroff'])
    # print("Turning off VBox")
    # # Show total time in hh:mm:ss
    # f.time_me(start)

    # return detect, 0.5

import gen_single_vec
import concat_2_vector
import gen_image
import check_functionality_using_model


def check_functionality(original_mal, mutation):
    result = 0
    check_functionality_folder = "C:\\Users\\thanh\\Downloads\\KLTN\AIMER-RL\\samples\\check_functionality"

    #Tạo vector original và mutation
    malware_name = os.path.splitext(os.path.basename(original_mal))[0]
    mutation_name = os.path.splitext(os.path.basename(mutation))[0]
    print(malware_name)
    vector_folder = os.path.join(check_functionality_folder, malware_name)
    if os.path.exists(vector_folder) == False:
        os.makedirs(vector_folder)
    print("Original malware: " + original_mal)
    print("Current mutation: " + mutation)

    gen_single_vec.gen_vec(original_mal, vector_folder)
    gen_single_vec.gen_vec(mutation, vector_folder)
    print("=======================================")

    #Nối 2 vector vừa tạo
    print("Concat 2 vectors")
    original_mal_vector = os.path.join(vector_folder,malware_name + ".txt")
    mutation_vector = os.path.join(vector_folder,mutation_name + ".txt")
    if os.path.exists(original_mal_vector):
        if os.path.exists(mutation_vector):
            concat_2_vector.concatenate_files(original_mal_vector, mutation_vector, vector_folder)
            print("Concat 2 vectors successfully!!!")
        #Tạo hình ảnh từ vectort tổng hợp
        image_name = f"concatenated_{malware_name}.txt_{mutation_name}"
        vector_path = os.path.join(vector_folder, image_name + ".txt")
        if(os.path.exists(vector_path)):
            gen_image.gen_image(image_name, vector_path, vector_folder)

            #Check functionality bằng model đã train trước
            image_path = os.path.join(vector_folder, image_name + ".jpg")
            print("image path: " + image_path)
            # if(check_functionality_using_model.check_functionality(image_path)):
            #     valid = True
            # else: 
            #     valid = False
            # print(check_functionality_using_model.check_functionality(image_path))
            result = check_functionality_using_model.check_functionality(image_path)
            print(result)
            print("====")
            
    return result
# import os
# from concurrent.futures import ThreadPoolExecutor

# def check_functionality(original_mal, mutation):
#     result = 0
#     check_functionality_folder = "C:\\Users\\thanh\\Downloads\\KLTN\\AIMER-RL\\samples\\check_functionality"

#     # Extract names and set up folders
#     malware_name = os.path.splitext(os.path.basename(original_mal))[0]
#     mutation_name = os.path.splitext(os.path.basename(mutation))[0]
#     vector_folder = os.path.join(check_functionality_folder, malware_name)

#     if not os.path.exists(vector_folder):
#         os.makedirs(vector_folder)
    
#     print(f"Original malware: {original_mal}")
#     print(f"Current mutation: {mutation}")

#     # Generate vectors concurrently
#     with ThreadPoolExecutor() as executor:
#         futures = [
#             executor.submit(gen_single_vec.gen_vec, original_mal, vector_folder),
#             executor.submit(gen_single_vec.gen_vec, mutation, vector_folder)
#         ]
#         for future in futures:
#             future.result()

#     print("Vectors generated.")
#     print("=======================================")

#     # Concat two vectors
#     print("Concatenating vectors")
#     original_mal_vector = os.path.join(vector_folder, f"{malware_name}.txt")
#     mutation_vector = os.path.join(vector_folder, f"{mutation_name}.txt")

#     if os.path.exists(original_mal_vector) and os.path.exists(mutation_vector):
#         concat_2_vector.concatenate_files(original_mal_vector, mutation_vector, vector_folder)
#         print("Vectors concatenated successfully.")

#         # Generate image from concatenated vector
#         image_name = f"concatenated_{malware_name}_{mutation_name}"
#         vector_path = os.path.join(vector_folder, f"{image_name}.txt")

#         if os.path.exists(vector_path):
#             gen_image.gen_image(image_name, vector_path, vector_folder)
#             image_path = os.path.join(vector_folder, f"{image_name}.jpg")
#             print(f"Image path: {image_path}")

#             # Check functionality using the trained model
#             result = check_functionality_using_model.check_functionality(image_path)
#             print(result)
#             print("====")

#     return result

# def restart_VM():
    vm = "Windows7"
    
    print("***Restarting VM")
    while True:
        try:
            
            # Shutdown the VM
            call(['VBoxManage', 'controlvm', vm, 'poweroff'])

            # Start & restore the VM (headless = invisible)
            state = check_output(['VBoxManage', 'showvminfo', vm]).decode('UTF-8')
            
            if "powered off" in state or "saved" in state or "aborted" in state:
                call(['VBoxManage', 'snapshot', vm, 'restore', 'Safe1'])
                call(['VBoxManage', 'startvm', vm, '--type', 'headless'])
            elif "paused" in state:
                call(['VBoxManage', 'controlvm', vm, 'resume', '--type', 'headless'])
            break
        except CalledProcessError as err:
            state = err
            print("Erro restarting VM, trying again")
            continue
        
        
# def turnoff_VM():
    vm = "Windows7"
    
    print("Turning off VM")
    while True:
        try:
            # Shutdown the VM
            call(['VBoxManage', 'controlvm', vm, 'poweroff'])
            break
        except CalledProcessError as err:
            print("Error when turning off VM, trying again")
            continue
        