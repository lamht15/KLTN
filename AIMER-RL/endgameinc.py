import torch
import torch.nn.functional as F
from MalConv import MalConv
import lightgbm as lgb
import numpy as np

MALCONV_MODEL_PATH = 'models/malconv/malconv.checkpoint'
NONNEG_MODEL_PATH = 'models/nonneg/nonneg.checkpoint'
EMBER_MODEL_PATH = 'models/ember/ember_model.txt'

class MalConvModel(object):
    def __init__(self, model_path, name='malconv'): 
        self.model = MalConv(channels=256, window_size=512, embd_size=8).train()
        weights = torch.load(model_path,map_location='cpu')
        self.model.load_state_dict( weights['model_state_dict'])
        self.__name__ = name

    def predict(self, bytez):
        temp = np.frombuffer(bytez,dtype=np.uint8)[np.newaxis,:] 
        _inp = torch.from_numpy( temp )
        with torch.no_grad():
            outputs = F.softmax( self.model(_inp), dim=-1)

        return outputs.detach().numpy()[0,1]
    
def load_malconv():
    return MalConvModel(MALCONV_MODEL_PATH)

def load_nonneg_malconv():
    return MalConvModel(NONNEG_MODEL_PATH, name='nonneg_malconv')
    