import boto3
import json
import pysftp
import os 
import logging
import fnmatch
import paramiko
import io
from stat import S_ISDIR, S_ISREG
from datetime import datetime
from getSecret import get_secret


logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
#boto3.set_stream_logger('')

def lambda_handler(event, context):
    log.debug(event)
    
    bucket_name = event.get('TargetBucketName')
    log.debug('bucket_name from evenet' + str(bucket_name))
    bucket_name = 'optus-development-dev-oft-gateway'
    
    d1  = datetime.today().strftime('%Y-%m-%d-%H')
    log.debug('d1 : ' + d1)
   
   
   
    log.debug('bucketName=== {}'.format(bucket_name))
    #s3_client = boto3.client(service_name='s3')
    
    #my_bucket = s3_client.Bucket(Bucket=bucket_name)
    
    #for my_bucket_object in my_bucket.objects.all():
     #print(my_bucket_object)
    
    
    s3 = boto3.resource('s3')
    my_bucket = s3.Bucket(bucket_name)

    inProcessFile = 'prepaid-sales/digital-orders' + '-d1' 
    
    inProcessExist = False
    
    for object_summary in my_bucket.objects.filter(Prefix="prepaid-sales/digital-orders"):
     if (object_summary.key == inProcessFile):
      inProcessExist = True 
    
    
    if inProcessExist:
     print(' there is in progress file')
    
     
    
    #sftp_host = event.get('SftpHost')
    sftp_host = 's-ea7d1dab058d48bab.server.transfer.ap-southeast-2.amazonaws.com'
    
    #sftp_user = event.get('SftpUser')
    sftp_user = 'oftp-dev2'
    
    #sftp_password_secret_arn = event.get('SftpSecretArn')
    #sftp_private_key_auth = event.get('SftpPrivateKeyAuth', 'False').lower() == 'true'
    sftp_private_key_auth = True
    #sftp_files = event.get('Files')
    
   
   
    
    
    
    
   # for my_bucket_object in my_bucket.objects.filter(Prefix="prepaid-sales/digital-orders"):
    #    print(my_bucket_object.key)
    
    
    
   
    
    #sftp_host = event.get('SftpHost')
    #sftp_user = event.get('SftpUser')
    #sftp_password_secret_arn = event.get('SftpSecretArn')
 
    #sftp_private_key_auth = event.get('SftpPrivateKeyAuth', 'False').lower() == 'true'
    #sftp_files = event.get('Files')
    
    sftp_password_secret_arn = 'prepaid-sales-oft-tf-private-key'

   # Fetch the password from Secrets Manager
    #log.info('Fetching Secret: {}'.format(getSecret.get_secret())
    secretsmanager_client = boto3.client(service_name='secretsmanager')
    sftp_password = secretsmanager_client.get_secret_value(SecretId=sftp_password_secret_arn)['SecretString']
  
  
    log.debug('Retrieved secret not formated : ' + sftp_password)


     
    cnOpts = pysftp.CnOpts()
    cnOpts.hostkeys = None
   
    
    log.debug('Connecting to SFTP server: {}'.format(sftp_host))    
    if sftp_private_key_auth:
       with open("/tmp/private_key1", "w") as file:
         
         file.write(sftp_password)
     
       sftp = pysftp.Connection(sftp_host, username=sftp_user, private_key='/tmp/private_key1', cnopts=cnOpts)
       log.debug('connection successful')
       
    #   sftp = pysftp.Connection(sftp_host, username=sftp_user, private_key='/tmp/oft-tf', cnopts=cnOpts)
    #   os.remove('/tmp/private_key1')
  #  else:
  #      sftp = pysftp.Connection(sftp_host, username=sftp_user, password=sftp_password, cnopts=cnOpts)
  #  
  #  for sftp_file in sftp_files:
  #      log.info ('SourceFile: {}'.format(sftp_file.get('SourceFile')))
  #      log.info ('TargetPath: {}'.format(sftp_file.get('TargetPath')))
  #      path, file = sftp_file.get('SourceFile').rsplit('/', 1)
  #      target_path = sftp_file.get('TargetPath')
  #      log.info ('Retrieving directory list for path: {} '.format(path))
  #      sftp_list_dir_attr = sftp.listdir_attr(path)
  #      log.debug("Directory listing: {}".format(sftp_list_dir_attr))
  #      for entry in sftp_list_dir_attr:
            # If filename matches pattern AND is not a directory AND is a regular file
   #         if fnmatch.fnmatch(entry.filename, file) and not S_ISDIR(entry.st_mode) and S_ISREG(entry.st_mode): 
    #            filename = entry.filename
    #            log.info("Retrieving file: {}/{}".format(path,filename))
    #            sftp.get('{}/{}'.format(path, filename), localpath='/tmp/sftp_file', preserve_mtime=True)
    #            log.info('Copying file to S3 bucket and path: s3://{}/{}/{}'.format(bucket_name, target_path.lstrip('/'), filename))
    #            s3_client = boto3.client(service_name='s3')
    #            s3_client = s3_client.upload_file(Filename='/tmp/sftp_file', Bucket=bucket_name, Key='{}/{}'.format(target_path.lstrip('/'), filename))
    #            os.remove('/tmp/sftp_file')
    #        else:
    #            log.debug('Unmatched: {}. Directory: {}'.format(entry.filename, S_ISDIR(entry.st_mode)))
    
    #log.info('Closing connection to SFTP server: {}'.format(sftp_host))
    #sftp.close()
    
    
    return True
