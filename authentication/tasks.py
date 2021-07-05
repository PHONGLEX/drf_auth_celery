from celery.decorators import task
from celery.utils.log import get_task_logger

from .utils import EmailHelper

logger = get_task_logger(__name__)


@task(name="send_email_task")
def send_email_task(data):
    logger.info("Sent email")
    return EmailHelper.send_mail(data)
