from alembic import context
from app.config import Settings
from app.database.session import connect
from app.database.models import Base

engine, _ = connect(Settings().database_url)
with engine.connect() as connection:
    context.configure(
        connection=connection, target_metadata=Base.metadata, compare_type=True
    )
    with context.begin_transaction():
        context.run_migrations()
