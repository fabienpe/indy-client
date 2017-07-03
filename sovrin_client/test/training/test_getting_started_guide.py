import logging

from sovrin_client.test.training.getting_started_future import *
from sovrin_client.test.training.log_messages import setup_message_logging, print_log_uid_database, \
    add_pool_uids, add_agent_uids
# noinspection PyUnresolvedReferences
from sovrin_node.test.conftest import tconf


def getting_started(base_dir=None):

    ####################################
    #  Setup
    ####################################

    if base_dir is None:
        base_dir = TemporaryDirectory().name
    logging.info("### Base directory is: {} ###".format(base_dir))

    demo_setup_logging(base_dir)
    setup_message_logging(base_dir)

    logging.info("### Start creating pool and stewards ###")
    pool, steward = create_local_pool(base_dir)

    add_pool_uids(pool, steward)

    logging.info("### Start creating and starting agents ###")
    agents = demo_start_agents(pool, pool, base_dir)

    add_agent_uids(agents)


    # ###################################
    #  Alice's Wallet
    # ###################################


    logging.info("### Start creating Alice client ###")
    alice_client = pool.create_client(5403, "Alice's client")

    logging.info("### Start creating Alice wallet ###")
    alice_wallet = Wallet("Alice's Wallet")

    logging.info("### Start creating Alice agent ###")
    alice_agent = WalletedAgent(name="Alice",
                                basedirpath=base_dir,
                                client=alice_client,
                                wallet=alice_wallet,
                                port=8786)

    logging.info("### Start adding identifier for Alice agent ###")
    alice_agent.new_identifier()
    pool.add(alice_agent)
    pool.runFor(1)

    add_agent_uids([alice_agent])

    ####################################
    #  Faber Invitation
    ####################################

    print(FABER_INVITE)

    logging.info("### Alice loads Faber's invitation: ### {}".format(FABER_INVITE))
    link_to_faber = alice_agent.load_invitation_str(FABER_INVITE)

    print(link_to_faber)

    logging.info("### Alice sync link with Faber ###")
    alice_agent.sync(link_to_faber.name)
    demo_wait_for_sync(pool, link_to_faber)

    print(link_to_faber)

    logging.info("### Alice accepts Faber's invitation ###")
    alice_agent.accept_invitation(link_to_faber)
    demo_wait_for_accept(pool, link_to_faber)

    print(link_to_faber)

    logging.info("### Alice pings Faber ###")
    alice_agent.sendPing("Faber College")
    demo_wait_for_ping(pool)

    ####################################
    #  Transcription Claim
    ####################################

    logging.info("### Alice wait for Transcript claim to be available  ###")
    demo_wait_for_claim_available(pool, link_to_faber, 'Transcript')
    claim_to_request = link_to_faber.find_available_claim(name='Transcript')

    print(claim_to_request)

    logging.info("### Alice send claim request to Faber ###")
    pool.run(alice_agent.send_claim(link_to_faber, claim_to_request))
    demo_wait_for_claim_received(pool, alice_agent, 'Transcript')
    claims = pool.run(alice_agent.prover.wallet.getAllClaims())

    print(claims)

    ####################################
    #  Acme Invitation
    ####################################

    print(ACME_INVITE)
    logging.info("### Alice loads Acme's invitation: {} ###".format(ACME_INVITE))
    link_to_acme = alice_agent.load_invitation_str(ACME_INVITE)

    print(link_to_acme)

    logging.info("### Alice sync link with Acme ###")
    alice_agent.sync(link_to_acme.name)
    demo_wait_for_sync(pool, link_to_acme)

    print(link_to_acme)

    logging.info("### Alice accepts Acme's invitation ###")
    alice_agent.accept_invitation(link_to_acme)
    demo_wait_for_accept(pool, link_to_acme)

    print(link_to_acme)

    logging.info("### Alice sends Job Application ###")
    job_application_request = link_to_acme.find_proof_request(name='Job-Application')
    print(job_application_request)
    alice_agent.sendProof(link_to_acme, job_application_request)

    ####################################
    #  Job-Certificate Claim
    ####################################

    logging.info("### Alice wait for Job-Certificate to be available  ###")
    demo_wait_for_claim_available(pool, link_to_acme, 'Job-Certificate')

    print(link_to_acme)

    job_certificate = link_to_acme.find_available_claim(name='Job-Certificate')

    print(job_certificate)

    logging.info("### Alice send claim request to Acme ###")
    pool.run(alice_agent.send_claim(link_to_acme, job_certificate))

    demo_wait_for_claim_received(pool, alice_agent, 'Job-Certificate')

    claims = pool.run(alice_agent.prover.wallet.getAllClaims())

    print(claims)

    ####################################
    #  Thrift Invitation
    ####################################

    print(THRIFT_INVITE)
    logging.info("### Alice loads Thrift's invitation: {} ###".format(THRIFT_INVITE))
    link_to_thrift = alice_agent.load_invitation_str(THRIFT_INVITE)

    print(link_to_thrift)

    logging.info("### Alice sync link with Thrift ###")
    alice_agent.sync(link_to_thrift.name)

    demo_wait_for_sync(pool, link_to_thrift)

    print(link_to_thrift)

    logging.info("### Alice accepts Thrift's invitation ###")
    alice_agent.accept_invitation(link_to_thrift)

    demo_wait_for_accept(pool, link_to_thrift)

    print(link_to_thrift)

    ####################################
    #  Proof to Thrift
    ####################################

    logging.info("### Alice sends Loan Application Basic to Thrift ###")
    load_basic_request = link_to_thrift.find_proof_request(name='Loan-Application-Basic')

    print(load_basic_request)

    alice_agent.sendProof(link_to_thrift, load_basic_request)

    demo_wait_for_proof(pool, load_basic_request)

    #######

    logging.info("### Alice sends Loan Application KYC to Thrift ###")
    load_kyc_request = link_to_thrift.find_proof_request(name='Loan-Application-KYC')

    print(load_kyc_request)

    alice_agent.sendProof(link_to_thrift, load_kyc_request)

    demo_wait_for_proof(pool, load_kyc_request)

    pool.shutdownSync()

if __name__ == "__main__":
    getting_started()
    print_log_uid_database()
    print("### END ###")
